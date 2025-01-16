# certificate-controller
> copy and modify github.com/kubernetes/kubernetes/cmd/kube-controller-manager/app/certificates.go

从Kubernetes 1.22版本开始，稳定版的CertificateSigningRequest API(`certificates.k8s.io/v1`)不允许将`singerName`设置为`kubernetes.io/legacy-unknown`。为了使用Kubernetes证书保护工作负载，实现一个自定义的证书签署者。该自定义签署者包含一下信息:

- 信任分发: 没有。这个签名者在 Kubernetes 集群中没有标准的信任或分发
- 许可的主体: 全部
- 允许的x509扩展: 允许subjectAltName和key usage扩展，并弃用其他扩展
- 允许的密钥用法: 必须包含`["server auth"]`，但不能包含`["digital signature", "key encipherment", "server auth"]`之外的键
- 过期时间/证书有效期: 1年（默认值和最大值）
- 允许/不允许CA位: 不允许