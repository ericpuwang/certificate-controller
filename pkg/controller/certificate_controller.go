package controller

import (
	"context"
	"encoding/pem"
	"fmt"
	"math/rand"
	"time"

	"github.com/ericpuwang/certificate-controller/pkg/options"
	"github.com/ericpuwang/certificate-controller/pkg/signer"
	capi "k8s.io/api/certificates/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	certificatelisters "k8s.io/client-go/listers/certificates/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

const signerName = "cms.io/app-serving"

type CertificateController struct {
	client      kubernetes.Interface
	queue       workqueue.RateLimitingInterface
	csrInformer cache.SharedIndexInformer
	csrLister   certificatelisters.CertificateSigningRequestLister
	signer      signer.CustomerSigner
}

func NewCertificateController(opts *options.CertificateControllerOptions) (*CertificateController, error) {
	cc := &CertificateController{
		queue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "certificate"),
	}
	err := cc.setClient(opts.KubeConfig)
	if err != nil {
		return nil, err
	}

	factor := rand.Float64() + 1
	resyncPeriod := time.Duration(12 * time.Hour * time.Duration(factor))
	informerFactory := informers.NewSharedInformerFactory(cc.client, resyncPeriod)
	certificateInfomer := informerFactory.Certificates().V1().CertificateSigningRequests()
	cc.csrInformer = certificateInfomer.Informer()
	cc.csrLister = certificateInfomer.Lister()
	cc.csrInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			csr := obj.(*capi.CertificateSigningRequest)
			klog.V(4).Info("Adding certificate request", "csr", csr.Name)
			cc.enqueueCertificateRequest(obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			csr := oldObj.(*capi.CertificateSigningRequest)
			klog.V(4).Info("Updating certificate request", "csr", csr.Name)
			cc.enqueueCertificateRequest(newObj)
		},
		DeleteFunc: func(obj interface{}) {
			csr, ok := obj.(*capi.CertificateSigningRequest)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					klog.V(2).Info("Couldn't get object from tombstone", "object", obj)
					return
				}
				csr, ok = tombstone.Obj.(*capi.CertificateSigningRequest)
				if !ok {
					klog.V(2).Info("Tombstone containerd object that is not a CSR", "object", obj)
					return
				}
			}
			klog.V(4).Info("Deleting certificate request", "csr", csr.Name)
			cc.enqueueCertificateRequest(obj)
		},
	})
	return cc, nil
}

func (cc *CertificateController) Run(ctx context.Context) {
	defer utilruntime.HandleCrash()
	defer cc.queue.ShutDown()

	klog.Info("Starting certificate controller", "name", signerName)
	defer func() {
		klog.Info("Shutting down certificate controller", "name", signerName)
	}()

	go cc.csrInformer.Run(ctx.Done())

	if !cache.WaitForNamedCacheSync(fmt.Sprintf("certificate-%s", signerName), ctx.Done(), cc.csrInformer.HasSynced) {
		return
	}

	for i := 0; i < 3; i++ {
		go wait.UntilWithContext(ctx, cc.worker, time.Second)
	}
	<-ctx.Done()
}

func (cc *CertificateController) worker(ctx context.Context) {
	for cc.processNextItem(ctx) {
	}
}

func (cc *CertificateController) processNextItem(ctx context.Context) bool {
	key, quit := cc.queue.Get()
	if quit {
		return false
	}
	defer cc.queue.Done(key)

	if err := cc.sync(ctx, key.(string)); err != nil {
		if errors.IsConflict(err) {
			cc.queue.AddAfter(key, time.Second)
			return true
		}
		cc.queue.AddRateLimited(key)
		utilruntime.HandleError(fmt.Errorf("sync %v failed with : %v", key, err))
		return true
	}

	cc.queue.Forget(key)
	return true
}

func (cc *CertificateController) sync(ctx context.Context, key string) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).Infof("Finished syncing certificate request %q (%v)", key, time.Since(startTime))
	}()

	csr, err := cc.csrLister.Get(key)
	if errors.IsNotFound(err) {
		klog.V(3).Infof("csr has been deleted: %v", key)
		return nil
	}
	if err != nil {
		return err
	}

	if len(csr.Status.Certificate) > 0 {
		return nil
	}

	csr = csr.DeepCopy()
	return cc.handler(ctx, csr)
}

func (cc *CertificateController) handler(ctx context.Context, csr *capi.CertificateSigningRequest) error {
	if !isCertificateRequestApproved(csr) || hasTrueCondition(csr, capi.CertificateFailed) {
		return nil
	}
	if csr.Spec.SignerName != signerName {
		return nil
	}
	certificateRequest, err := parseCSR(csr.Spec.Request)
	if err != nil {
		klog.ErrorS(err, "Unable to parse csr %q", csr.Name)
		return err
	}
	if err := certificateRequest.CheckSignature(); err != nil {
		klog.ErrorS(err, "Unable to verify certificate request signature")
		return err
	}
	if err := validateAppServingCSR(certificateRequest, csr.Spec.Usages); err != nil {
		klog.ErrorS(err, "Invalid certificate signing request")
		return err
	}

	certificate, err := cc.signer.Sign(certificateRequest, csr.Spec.Usages, csr.Spec.ExpirationSeconds)
	if err != nil {
		klog.Error(err)
		return err
	}

	csr.Status.Certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	_, err = cc.client.CertificatesV1().CertificateSigningRequests().UpdateStatus(ctx, csr, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (cc *CertificateController) enqueueCertificateRequest(obj any) {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key from object %+v: %+v", obj, err))
		return
	}
	cc.queue.Add(key)
}

func (cc *CertificateController) setClient(kubeconfig string) error {
	var config *rest.Config
	var err error
	if kubeconfig == "" {
		config, err = rest.InClusterConfig()
	} else {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	if err != nil {
		return err
	}

	cc.client, err = kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}
	return nil
}
