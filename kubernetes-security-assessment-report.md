# Kubernetes Security Vulnerability Assessment Report

**Date:** January 27, 2026  
**Assessment Type:** Comprehensive Kubernetes Security Audit  
**Scope:** Local Server Environment  
**Report Status:** ⚠️ ENVIRONMENT ASSESSMENT COMPLETED

---

## Executive Summary

This report documents the findings from a comprehensive Kubernetes security assessment attempt on the local Linux server environment. The assessment was conducted using the MCP Kubernetes Security Server with integrated security scanning tools.

### Critical Finding: No Kubernetes Cluster Detected

**Status:** ❌ **NO KUBERNETES CLUSTER FOUND**

| Category | Status | Details |
|----------|--------|---------|
| **Environment** | Ubuntu 24.04.3 LTS (x86_64) | Container-based environment |
| **Kubernetes Cluster** | ❌ Not Found | No Kubernetes processes detected |
| **kubectl** | ❌ Not Installed | Command-line tool not available |
| **Docker** | ❌ Not Accessible | Docker daemon not accessible |
| **K3s/MicroK8s** | ❌ Not Found | Lightweight K8s distributions not present |

---

## 1. Environment Analysis

### Server Information

| Property | Value |
|----------|-------|
| Operating System | Ubuntu 24.04.3 LTS (Noble Numbat) |
| Kernel | Linux 4.4.0 |
| Architecture | x86_64 |
| Environment Type | Containerized (runsc) |
| Home Directory | /home/claude |
| User | root |

### Available Security Tools (MCP Server)

The MCP Kubernetes Security Server reported the following tool availability:

| Tool | Status | Purpose | Availability |
|------|--------|---------|--------------|
| **Kubescape** | ✅ Ready | NSA/CISA/CIS Kubernetes security framework | 100% |
| **Popeye** | ✅ Ready | Kubernetes cluster sanitizer | 100% |
| **RBAC-tool** | ✅ Ready | RBAC analysis and visualization | 100% |
| **Kubesec** | ✅ Ready | Kubernetes manifest security analyzer | 100% |
| **Kube-bench** | ❌ Unavailable | CIS Kubernetes benchmark testing | 0% |
| **Trivy** | ❌ Unavailable | Container vulnerability scanner | 0% |
| **Falco** | ❌ Unavailable | Runtime security monitoring | 0% |

**Total Tools Available:** 4 out of 7 (57.14%)

### MCP Server Health

| Metric | Value | Status |
|--------|-------|--------|
| Server Status | Healthy | ✅ |
| Version | 1.0.0 | ✅ |
| Uptime | 3.67 hours | ✅ |
| Commands Executed | 20 | ✅ |
| Success Rate | 25.0% | ⚠️ |
| Cache Hit Rate | 44.4% | ✅ |
| CPU Usage | 11.74% | ✅ |
| Memory Usage | 39.70% | ✅ |

---

## 2. Assessment Attempts and Findings

### 2.1 Cluster Discovery Scan

**Objective:** Identify and connect to Kubernetes cluster

| Check | Command/Tool | Result | Status |
|-------|--------------|--------|--------|
| Kubernetes Processes | `ps aux \| grep kube` | No processes found | ❌ |
| kubectl Command | `kubectl get nodes` | Command not found | ❌ |
| Docker Daemon | `docker ps` | Not accessible | ❌ |
| K3s Service | Process check | Not running | ❌ |
| MicroK8s | Process check | Not running | ❌ |
| Kubescape Connection | MCP tool call | Connection failed | ❌ |
| Popeye Connection | MCP tool call | Connection failed | ❌ |

### 2.2 Connection Issues

When attempting to use security tools, the following errors were encountered:

```
Error: ('Connection aborted.', RemoteDisconnected('Remote end closed connection without response'))
```

**Root Cause Analysis:**
- No Kubernetes API server available for tools to connect to
- Security tools require an active Kubernetes cluster to scan
- MCP server tools are functional but have no target cluster

---

## 3. Security Assessment Limitations

### What Could Not Be Assessed

Due to the absence of a Kubernetes cluster, the following security assessments could not be completed:

| Assessment Category | Description | Impact |
|---------------------|-------------|--------|
| **Node Security** | Kernel parameters, system hardening, container runtime | Cannot assess |
| **Pod Security** | Pod Security Standards, SecurityContext, capabilities | Cannot assess |
| **RBAC Configuration** | Roles, ClusterRoles, RoleBindings, privilege escalation | Cannot assess |
| **Network Policies** | Ingress/egress rules, microsegmentation | Cannot assess |
| **Container Security** | Image vulnerabilities, runtime security | Cannot assess |
| **CIS Benchmark** | Compliance with CIS Kubernetes Benchmark | Cannot assess |
| **NSA Hardening** | NSA/CISA Kubernetes Hardening Guide compliance | Cannot assess |
| **Secrets Management** | Secret encryption, external secret stores | Cannot assess |
| **Audit Logging** | API server audit logs, compliance | Cannot assess |
| **Admission Control** | PodSecurityPolicy, OPA, Kyverno policies | Cannot assess |

---

## 4. Recommendations for Kubernetes Deployment

Since no Kubernetes cluster exists, here are recommendations for setting up a secure Kubernetes environment:

### 4.1 Quick Setup Options

| Option | Description | Use Case | Complexity |
|--------|-------------|----------|------------|
| **Minikube** | Local Kubernetes for development | Learning, testing | Low |
| **K3s** | Lightweight Kubernetes | Edge, IoT, development | Low |
| **MicroK8s** | Minimal Kubernetes by Canonical | Development, production | Low |
| **Kind** | Kubernetes IN Docker | CI/CD, testing | Low |
| **kubeadm** | Production-grade cluster setup | Production clusters | High |

### 4.2 Installation Guide: K3s (Recommended)

K3s is recommended for this environment due to its simplicity and security features.

#### Step 1: Install K3s

```bash
# Install K3s server
curl -sfL https://get.k3s.io | sh -

# Check status
sudo systemctl status k3s

# Verify installation
sudo k3s kubectl get nodes
```

#### Step 2: Configure kubectl Access

```bash
# Create kubectl config
mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $(id -u):$(id -g) ~/.kube/config

# Test connection
kubectl get nodes
```

#### Step 3: Install Security Tools

```bash
# Install Kubescape
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash

# Install Trivy
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy

# Install kube-bench
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml

# Install Popeye
wget https://github.com/derailed/popeye/releases/download/v0.11.1/popeye_Linux_x86_64.tar.gz
tar -xzf popeye_Linux_x86_64.tar.gz
sudo mv popeye /usr/local/bin/
```

---

## 5. Security Best Practices for New Kubernetes Clusters

### 5.1 Immediate Security Hardening Steps

| Priority | Category | Action | Command/Configuration |
|----------|----------|--------|----------------------|
| 🔴 **Critical** | API Server | Enable audit logging | `--audit-log-path=/var/log/audit.log` |
| 🔴 **Critical** | RBAC | Disable anonymous auth | `--anonymous-auth=false` |
| 🔴 **Critical** | Secrets | Enable encryption at rest | Configure EncryptionConfiguration |
| 🟡 **High** | Network | Implement network policies | Create NetworkPolicy resources |
| 🟡 **High** | Pod Security | Enable Pod Security Admission | Use restricted policy |
| 🟡 **High** | Container Runtime | Use containerd or CRI-O | Avoid Docker if possible |
| 🟢 **Medium** | Admission | Deploy admission controllers | OPA Gatekeeper, Kyverno |
| 🟢 **Medium** | Monitoring | Deploy Falco for runtime | Install Falco DaemonSet |

### 5.2 RBAC Configuration Guidelines

#### Principle of Least Privilege

**DO:**
- ✅ Create specific Roles for each application
- ✅ Use RoleBindings for namespace-scoped permissions
- ✅ Limit ClusterRole usage
- ✅ Regularly audit ServiceAccount permissions
- ✅ Disable default ServiceAccount auto-mounting

**DON'T:**
- ❌ Use `cluster-admin` ClusterRole for applications
- ❌ Grant wildcard (`*`) permissions
- ❌ Use ClusterRoleBindings unnecessarily
- ❌ Allow privilege escalation without justification

#### Example Secure Role

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-reader
  namespace: production
rules:
- apiGroups: [""]
  resources: ["pods", "services"]
  verbs: ["get", "list", "watch"]
# NO create, update, delete, or wildcard permissions
```

### 5.3 Pod Security Standards

Implement Pod Security Admission with these standards:

| Level | Description | Restrictions |
|-------|-------------|--------------|
| **Privileged** | Unrestricted policy | None - avoid in production |
| **Baseline** | Minimally restrictive | Prevents known privilege escalations |
| **Restricted** | Heavily restricted | Defense-in-depth best practices |

**Recommended Configuration:**

```yaml
# Enforce restricted policy in production
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

### 5.4 Network Security

#### Network Policy Example (Default Deny)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
# This denies all traffic by default
```

#### Network Policy Example (Allow Specific Traffic)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
```

### 5.5 Container Image Security

| Practice | Description | Tools |
|----------|-------------|-------|
| **Scan Images** | Scan for vulnerabilities before deployment | Trivy, Clair, Anchore |
| **Use Official Images** | Pull from trusted registries | Docker Hub (verified), Quay.io |
| **Minimal Base Images** | Use distroless or minimal base | `gcr.io/distroless/static` |
| **Image Signing** | Verify image signatures | Sigstore, Notary |
| **Private Registry** | Host images in private registry | Harbor, ECR, GCR |
| **Regular Updates** | Keep images updated | Automated scanning pipeline |

#### Secure Container Configuration

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 10000
    fsGroup: 10000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: myapp:v1.0
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
        - ALL
      readOnlyRootFilesystem: true
    resources:
      limits:
        cpu: "1"
        memory: "512Mi"
      requests:
        cpu: "100m"
        memory: "128Mi"
    volumeMounts:
    - name: tmp
      mountPath: /tmp
  volumes:
  - name: tmp
    emptyDir: {}
```

---

## 6. CIS Kubernetes Benchmark Overview

Once a cluster is deployed, perform CIS Kubernetes Benchmark testing. Key areas:

### 6.1 Control Plane Configuration

| Section | Description | Example Check |
|---------|-------------|---------------|
| **1.1** | Master Node Configuration Files | File permissions 644 or more restrictive |
| **1.2** | API Server | Authentication, authorization, encryption |
| **1.3** | Controller Manager | Service account credentials, profiling |
| **1.4** | Scheduler | Profiling disabled, secure communication |

### 6.2 etcd Configuration

| Check | Requirement | Command |
|-------|-------------|---------|
| **2.1** | Client cert auth | `--client-cert-auth=true` |
| **2.2** | Auto TLS | `--auto-tls=false` |
| **2.3** | Peer cert auth | `--peer-client-cert-auth=true` |
| **2.4** | Peer auto TLS | `--peer-auto-tls=false` |

### 6.3 Control Plane Configuration

| Check | Description | Pass Criteria |
|-------|-------------|---------------|
| **3.1** | Authentication | No anonymous auth |
| **3.2** | Authorization | RBAC enabled |
| **3.3** | Encryption | Secrets encrypted at rest |
| **3.4** | Audit | Comprehensive audit logs |
| **3.5** | Admission | ValidatingWebhookConfiguration |

### 6.4 Worker Node Security

| Check | Description | Implementation |
|-------|-------------|----------------|
| **4.1** | Kubelet config | Anonymous auth disabled |
| **4.2** | File permissions | Config files owned by root |
| **4.3** | Kernel hardening | AppArmor/SELinux enabled |

### 6.5 Policies

| Check | Description | Status |
|-------|-------------|--------|
| **5.1** | RBAC | Minimize permissions |
| **5.2** | Pod Security | Restricted policy enforced |
| **5.3** | Network | NetworkPolicies defined |
| **5.4** | Secrets | External secret management |
| **5.5** | Admission | Admission controllers active |

---

## 7. NSA/CISA Kubernetes Hardening Guide Checklist

### 7.1 Pod Security

- [ ] Implement Pod Security Admission (restricted)
- [ ] Run containers as non-root users
- [ ] Disable privilege escalation
- [ ] Drop all capabilities, add only required ones
- [ ] Use read-only root filesystems
- [ ] Configure resource limits
- [ ] Use seccomp, AppArmor, or SELinux

### 7.2 Network Security

- [ ] Implement default deny NetworkPolicies
- [ ] Use ingress and egress rules
- [ ] Enable TLS for all services
- [ ] Implement service mesh (Istio, Linkerd)
- [ ] Use network segmentation

### 7.3 Authentication and Authorization

- [ ] Disable anonymous authentication
- [ ] Use RBAC exclusively
- [ ] Implement least privilege access
- [ ] Audit RBAC permissions regularly
- [ ] Use external authentication (OIDC)
- [ ] Rotate credentials regularly

### 7.4 Data Security

- [ ] Enable encryption at rest for secrets
- [ ] Use external secret management (Vault, AWS Secrets Manager)
- [ ] Enable encryption in transit (TLS)
- [ ] Implement audit logging
- [ ] Protect sensitive data in logs

### 7.5 Workload and Runtime Security

- [ ] Scan container images for vulnerabilities
- [ ] Use minimal base images
- [ ] Sign and verify container images
- [ ] Implement runtime security monitoring (Falco)
- [ ] Use admission controllers (OPA, Kyverno)
- [ ] Regular security updates and patching

---

## 8. MITRE ATT&CK for Kubernetes

Understanding adversary tactics helps prioritize security controls:

### 8.1 Initial Access

| Technique | Description | Mitigation |
|-----------|-------------|------------|
| **Valid Accounts** | Compromised credentials | MFA, credential rotation |
| **Exploit Public-Facing Application** | Vulnerable services exposed | Regular patching, WAF |
| **Supply Chain Compromise** | Malicious container images | Image scanning, signing |

### 8.2 Execution

| Technique | Description | Mitigation |
|-----------|-------------|------------|
| **User Execution** | Malicious kubectl commands | RBAC restrictions, audit logs |
| **Container Administration** | `kubectl exec` abuse | Restrict exec permissions, audit |
| **Pod/Container Execution** | Malicious containers | Admission control, runtime monitoring |

### 8.3 Persistence

| Technique | Description | Mitigation |
|-----------|-------------|------------|
| **Valid Accounts** | Create new accounts | Monitor account creation |
| **Implant Container Image** | Backdoored images | Image scanning, immutable tags |
| **Kubernetes CronJob** | Scheduled malicious tasks | Audit CronJob creation |

### 8.4 Privilege Escalation

| Technique | Description | Mitigation |
|-----------|-------------|------------|
| **Privileged Container** | Run as privileged | Pod Security Standards |
| **Access Cloud Resources** | Cloud metadata API | Network policies, IMDS protection |
| **hostPath Mount** | Mount host filesystem | Restrict hostPath usage |

### 8.5 Defense Evasion

| Technique | Description | Mitigation |
|-----------|-------------|------------|
| **Clear Container Logs** | Remove evidence | Centralized logging |
| **Pod/Container Escape** | Break out of container | SecComp, AppArmor, runtime monitoring |
| **Modify Cloud Compute Infrastructure** | Alter cluster config | RBAC restrictions, audit logs |

---

## 9. Post-Deployment Security Validation

Once Kubernetes is deployed, run these validation checks:

### 9.1 Initial Security Scan Checklist

```bash
# 1. Run Kubescape NSA framework
kubescape scan framework nsa --format json --output nsa-results.json

# 2. Run Kubescape CIS benchmark
kubescape scan framework cis-v1.23-t1.0.1 --format json --output cis-results.json

# 3. Run kube-bench CIS checks
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs -f job/kube-bench

# 4. Run Popeye cluster sanitizer
popeye --save --output-file popeye-report.html

# 5. Scan container images with Trivy
trivy image <image-name>

# 6. Analyze RBAC with rbac-tool
kubectl rbac-tool whocan create pods -A
kubectl rbac-tool lookup -e admin

# 7. Scan Kubernetes manifests
kubesec scan pod.yaml

# 8. Deploy runtime security
kubectl apply -f https://raw.githubusercontent.com/falcosecurity/falco/master/deploy/kubernetes/falco-daemonset.yaml
```

### 9.2 Continuous Security Monitoring

| Activity | Frequency | Tool/Method |
|----------|-----------|-------------|
| **Vulnerability Scanning** | Daily | Trivy, automated CI/CD scans |
| **RBAC Audit** | Weekly | rbac-tool, custom scripts |
| **Compliance Check** | Weekly | Kubescape, kube-bench |
| **Cluster Sanitization** | Daily | Popeye |
| **Runtime Monitoring** | Continuous | Falco, Sysdig |
| **Audit Log Review** | Daily | Elasticsearch, Splunk |
| **Security Posture** | Monthly | Full security assessment |

---

## 10. Remediation Priority Matrix

When security issues are found, prioritize remediation using this matrix:

| Severity | Description | Response Time | Example Issues |
|----------|-------------|---------------|----------------|
| 🔴 **Critical** | Immediate exploitation risk | < 24 hours | Anonymous API access, no RBAC, privileged containers |
| 🟠 **High** | Significant security risk | < 7 days | Weak network policies, excessive permissions, unpatched CVEs |
| 🟡 **Medium** | Moderate security concern | < 30 days | Missing resource limits, outdated images, audit gaps |
| 🟢 **Low** | Best practice improvement | < 90 days | Documentation gaps, non-critical misconfigurations |

---

## 11. Security Tooling Comparison

### 11.1 Recommended Security Tool Stack

| Layer | Purpose | Recommended Tool | Alternative |
|-------|---------|------------------|-------------|
| **Image Scanning** | Vulnerability detection | Trivy | Clair, Anchore |
| **Compliance** | CIS/NSA benchmarks | Kubescape | kube-bench, Checkov |
| **RBAC Analysis** | Permission auditing | rbac-tool | kubectl can-i, Fairwinds RBAC Manager |
| **Manifest Security** | YAML security scan | Kubesec | Checkov, Datree |
| **Cluster Sanitizer** | Misconfig detection | Popeye | KubeLinter |
| **Runtime Security** | Threat detection | Falco | Sysdig, Tracee |
| **Admission Control** | Policy enforcement | OPA Gatekeeper | Kyverno |
| **Network Analysis** | Network policies | Cilium Hubble | Calico Enterprise |

### 11.2 Tool Selection Matrix

| Requirement | Trivy | Kubescape | kube-bench | Popeye | Falco |
|-------------|-------|-----------|------------|--------|-------|
| **Image Scanning** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **CIS Benchmark** | ❌ | ✅ | ✅ | ❌ | ❌ |
| **NSA Framework** | ❌ | ✅ | ❌ | ❌ | ❌ |
| **RBAC Audit** | ❌ | ✅ | ❌ | ✅ | ❌ |
| **Runtime Security** | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Cluster Health** | ❌ | ❌ | ❌ | ✅ | ❌ |
| **Easy Setup** | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| **CI/CD Integration** | ✅ | ✅ | ✅ | ✅ | ❌ |

---

## 12. Conclusion and Next Steps

### 12.1 Current Status

❌ **No Kubernetes cluster found in the environment**

The security assessment could not be completed because:
1. No Kubernetes cluster is currently running on this server
2. Required Kubernetes components (kubectl, API server) are not present
3. Security tools cannot connect to a non-existent cluster

### 12.2 Immediate Next Steps

#### Option 1: Deploy Kubernetes Cluster
1. ✅ Choose a Kubernetes distribution (K3s recommended)
2. ✅ Install Kubernetes following Section 4.2
3. ✅ Install security tools following Section 4.3
4. ✅ Re-run this security assessment
5. ✅ Implement security hardening from Section 5

#### Option 2: Connect to Existing Cluster
1. ✅ Install kubectl on this server
2. ✅ Configure kubeconfig file with cluster credentials
3. ✅ Verify connectivity: `kubectl get nodes`
4. ✅ Re-run this security assessment with cluster access

### 12.3 Expected Timeline

| Phase | Activity | Duration |
|-------|----------|----------|
| **Phase 1** | Cluster deployment | 30-60 minutes |
| **Phase 2** | Security tool installation | 20-30 minutes |
| **Phase 3** | Initial security scan | 15-30 minutes |
| **Phase 4** | Remediation planning | 2-4 hours |
| **Phase 5** | Implementation | 1-3 days |
| **Phase 6** | Validation | 2-4 hours |

### 12.4 Success Criteria

After proper deployment and remediation, aim for:

- ✅ **CIS Benchmark Score:** > 90%
- ✅ **NSA Framework Compliance:** > 85%
- ✅ **Critical Vulnerabilities:** 0
- ✅ **High Vulnerabilities:** < 5
- ✅ **RBAC Overprivileged Accounts:** 0
- ✅ **Pod Security Standard:** Restricted enforced
- ✅ **Network Policies:** Implemented across all namespaces
- ✅ **Runtime Monitoring:** Falco deployed and alerting

---

## 13. Additional Resources

### Documentation
- [Kubernetes Security Documentation](https://kubernetes.io/docs/concepts/security/)
- [NSA/CISA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [MITRE ATT&CK for Kubernetes](https://attack.mitre.org/matrices/enterprise/containers/)

### Security Tools
- [Kubescape](https://github.com/kubescape/kubescape)
- [Trivy](https://github.com/aquasecurity/trivy)
- [kube-bench](https://github.com/aquasecurity/kube-bench)
- [Popeye](https://github.com/derailed/popeye)
- [Falco](https://falco.org/)
- [OPA Gatekeeper](https://github.com/open-policy-agent/gatekeeper)

### Training
- [Kubernetes Security Essentials (LFS260)](https://training.linuxfoundation.org/training/kubernetes-security-essentials-lfs260/)
- [Certified Kubernetes Security Specialist (CKS)](https://www.cncf.io/certification/cks/)

---

## Report Metadata

| Property | Value |
|----------|-------|
| **Report Generated** | January 27, 2026 |
| **Assessment Duration** | N/A (No cluster available) |
| **Tools Used** | MCP Kubernetes Security Server (4/7 tools ready) |
| **Target Environment** | Ubuntu 24.04.3 LTS (Container) |
| **Cluster Status** | ❌ Not Found |
| **Report Version** | 1.0 |
| **Next Assessment** | After Kubernetes deployment |

---

**Report Generated by:** MCP Kubernetes Security Assessment Framework  
**Classification:** INTERNAL USE  
**Distribution:** Authorized Personnel Only

---

## Appendix A: Tool Command Reference

### Kubescape Commands
```bash
# Scan with NSA framework
kubescape scan framework nsa

# Scan with CIS framework
kubescape scan framework cis-v1.23-t1.0.1

# Scan specific namespace
kubescape scan --namespace production

# Scan workload
kubescape scan workload deployment/myapp -n production

# Scan image
kubescape scan image nginx:latest

# Generate HTML report
kubescape scan framework nsa --format html --output report.html
```

### Trivy Commands
```bash
# Scan container image
trivy image nginx:latest

# Scan filesystem
trivy fs /path/to/project

# Scan Kubernetes cluster
trivy k8s --report summary cluster

# Scan with severity filter
trivy image --severity HIGH,CRITICAL nginx:latest

# Save results to file
trivy image -f json -o results.json nginx:latest
```

### kube-bench Commands
```bash
# Run CIS benchmark
kube-bench

# Run for specific node type
kube-bench --targets master
kube-bench --targets node

# Output to JSON
kube-bench --json > results.json

# Run as Kubernetes job
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
```

### Popeye Commands
```bash
# Scan all namespaces
popeye

# Scan specific namespace
popeye -n production

# Save report
popeye --save --output-file report.html

# Use custom spinach config
popeye -f spinach.yaml

# JSON output
popeye -o json --save
```

### RBAC-tool Commands
```bash
# Check who can perform action
kubectl rbac-tool whocan create pods

# Check across all namespaces
kubectl rbac-tool whocan create pods -A

# Lookup subject permissions
kubectl rbac-tool lookup -e admin

# Generate visualizations
kubectl rbac-tool viz --outformat dot
```

### Kubesec Commands
```bash
# Scan local file
kubesec scan pod.yaml

# Scan stdin
cat pod.yaml | kubesec scan -

# Scan remote file
kubesec scan https://example.com/pod.yaml

# JSON output
kubesec scan pod.yaml -o json
```

---

## Appendix B: Sample Secure Configurations

### Secure Deployment Template
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
  namespace: production
  labels:
    app: secure-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: secure-app
  template:
    metadata:
      labels:
        app: secure-app
    spec:
      # Security Context for Pod
      securityContext:
        runAsNonRoot: true
        runAsUser: 10000
        fsGroup: 10000
        seccompProfile:
          type: RuntimeDefault
      
      # Service Account
      serviceAccountName: secure-app-sa
      automountServiceAccountToken: false
      
      # Containers
      containers:
      - name: app
        image: myregistry.io/secure-app:v1.2.3
        imagePullPolicy: Always
        
        # Security Context for Container
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 10000
          capabilities:
            drop:
            - ALL
            add:
            - NET_BIND_SERVICE
        
        # Resource Limits
        resources:
          requests:
            cpu: "100m"
            memory: "128Mi"
          limits:
            cpu: "500m"
            memory: "512Mi"
        
        # Liveness/Readiness Probes
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        
        # Volume Mounts
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: cache
          mountPath: /app/cache
      
      # Volumes
      volumes:
      - name: tmp
        emptyDir: {}
      - name: cache
        emptyDir: {}
      
      # Node Affinity
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchExpressions:
                - key: app
                  operator: In
                  values:
                  - secure-app
              topologyKey: kubernetes.io/hostname
```

### Secure NetworkPolicy
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: secure-app-policy
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: secure-app
  policyTypes:
  - Ingress
  - Egress
  
  ingress:
  # Allow from frontend only
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
  
  egress:
  # Allow to database
  - to:
    - podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432
  
  # Allow DNS
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: UDP
      port: 53
```

### Secure ServiceAccount RBAC
```yaml
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: secure-app-sa
  namespace: production
automountServiceAccountToken: false

---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secure-app-role
  namespace: production
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]
  resourceNames: ["app-secret"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: secure-app-binding
  namespace: production
subjects:
- kind: ServiceAccount
  name: secure-app-sa
  namespace: production
roleRef:
  kind: Role
  name: secure-app-role
  apiGroup: rbac.authorization.k8s.io
```

---

**END OF REPORT**
