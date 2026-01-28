# Kubernetes Security Assessment Report

**Date:** January 28, 2026  
**Cluster:** Kubernetes Worker Node (default namespace)  
**Assessment Tools:** Kubescape (NSA Framework), Popeye, RBAC-Tool, kube-bench (CIS), Nmap

---

## Executive Summary

This comprehensive security assessment identified **multiple critical and high-severity vulnerabilities** across the Kubernetes worker node environment. The overall compliance score is **53.9%** (NSA Framework), indicating significant security improvements are required.

### Key Findings:
- **Overall Compliance Score:** 53.9% (NSA Framework)
- **Popeye Score:** 80/100 (Grade: B)
- **Critical Issues:** 4
- **High Severity Issues:** 20+
- **Medium Severity Issues:** 40+
- **Total Failed Controls:** 9 (NSA Framework)

---

## 1. Kubernetes Security Vulnerability Scan

### 1.1 NSA Framework Compliance Results

| Category | Item | Status | Severity | Details |
|----------|------|--------|----------|---------|
| **Workload Security** | Non-root containers | ❌ FAIL | Medium | 8/8 deployments running as root |
| **Workload Security** | Allow privilege escalation | ❌ FAIL | Medium | 8/8 containers allow privilege escalation |
| **Workload Security** | Immutable container filesystem | ❌ FAIL | Low | 8/8 containers have writable root filesystem |
| **Workload Security** | Privileged container | ❌ FAIL | High | 2/8 containers running in privileged mode |
| **Workload Security** | Host PID/IPC privileges | ❌ FAIL | High | 1 deployment using hostPID/hostIPC |
| **Workload Security** | Linux hardening | ❌ FAIL | Medium | Missing seccomp, SELinux, capabilities drop |
| **Network Security** | Ingress and Egress blocked | ❌ FAIL | Medium | 8/8 pods lack NetworkPolicy protection |
| **Secrets** | Automatic mapping of service account | ❌ FAIL | Medium | 9/10 resources auto-mount service accounts |
| **Resource Management** | CPU limits | ❌ FAIL | High | 1/8 containers missing CPU limits |
| **Resource Management** | Memory limits | ❌ FAIL | High | 1/8 containers missing memory limits |
| **Access Control** | Administrative Roles | ✅ PASS | Medium | No overly permissive admin roles detected |
| **Access Control** | Prevent command execution | ✅ PASS | Medium | No containers allowing command execution |
| **Secrets** | Credentials in config files | ✅ PASS | High | No credentials found in configuration files |
| **Control Plane** | API server insecure port | ✅ PASS | Critical | Insecure port disabled |
| **Network** | HostNetwork access | ✅ PASS | High | No pods using hostNetwork |
| **Network** | Container hostPort | ✅ PASS | Medium | No containers using hostPort |

### 1.2 Detailed Resource Findings

| Resource | Control | Status | Severity | Issue |
|----------|---------|--------|----------|-------|
| `system-monitor-deployment` | Privileged container | ❌ FAIL | High | Container running with `privileged: true` |
| `system-monitor-deployment` | Host PID/IPC | ❌ FAIL | High | Using `hostPID: true` and `hostIPC: true` |
| `health-check-deployment` | Privileged container | ❌ FAIL | High | Container running with `privileged: true` |
| `internal-proxy-deployment` | Non-root containers | ❌ FAIL | Medium | Both containers running as root |
| `kubernetes-goat-home-deployment` | Non-root containers | ❌ FAIL | Medium | Container running as root |
| `build-code-deployment` | Non-root containers | ❌ FAIL | Medium | Container running as root |
| `batch-check-job` | Resource limits | ❌ FAIL | High | Missing CPU and memory limits |
| All Deployments | NetworkPolicy | ❌ FAIL | Medium | No NetworkPolicies protecting pods |

---

## 2. RBAC Misconfiguration Analysis

### 2.1 Critical Findings

| Subject | Finding | Severity | Details |
|---------|---------|----------|---------|
| `kubeadm:cluster-admins` (Group) | Privilege escalation via impersonate | 🔴 CRITICAL | Can impersonate any user/service account |
| `kubeadm:cluster-admins` (Group) | Privilege escalation via bind/escalate | 🔴 CRITICAL | Can bind roles and escalate privileges |
| `kubeadm:cluster-admins` (Group) | Create Node Proxy | 🔴 CRITICAL | Can create node proxies for Kubelet API access |
| `kubeadm:cluster-admins` (Group) | Install/Modify Admission Controllers | 🔴 CRITICAL | Can install/modify admission controllers |
| `istio-system/istiod` (SA) | Install/Modify Admission Controllers | 🔴 CRITICAL | Can install/modify admission controllers |

### 2.2 High Severity Findings

| Subject | Finding | Severity | Details |
|---------|---------|----------|---------|
| `kubeadm:cluster-admins` (Group) | Secret Readers | 🔴 HIGH | Can read all secrets cluster-wide |
| `istio-system/istiod` (SA) | Secret Readers | 🔴 HIGH | Can read secrets in multiple namespaces |
| `mcp-system/mcp-server` (SA) | Secret Readers | 🔴 HIGH | Can read secrets cluster-wide |
| `big-monolith/big-monolith-sa` (SA) | Secret Readers | 🔴 HIGH | Can read secrets |
| `kubeadm:cluster-admins` (Group) | Workload Creators & Editors | 🔴 HIGH | Can create/modify any workload |
| `mcp-system/mcp-server` (SA) | Workload Creators & Editors | 🔴 HIGH | Can create/modify workloads |
| `mcp-system/mcp-kube-bench` (SA) | Workload Creators & Editors | 🔴 HIGH | Can create/modify workloads |
| `kubeadm:cluster-admins` (Group) | Storage Manipulation | 🔴 HIGH | Can manipulate StorageClass, Volumes, PVCs |
| `kubeadm:cluster-admins` (Group) | Networking Manipulation | 🔴 HIGH | Can manipulate Services, Ingresses, NetworkPolicies |
| `istio-system/istiod` (SA) | Networking Manipulation | 🔴 HIGH | Can manipulate networking resources |
| `kubeadm:cluster-admins` (Group) | Create Ephemeral Containers | 🔴 HIGH | Can create ephemeral containers in pods |
| `kubeadm:cluster-admins` (Group) | Exec into Pod | 🔴 HIGH | Can exec into any pod |

### 2.3 RBAC Summary

- **Total Findings:** 20
- **Critical:** 4
- **High:** 16
- **Medium:** 0

---

## 3. Benchmark Scoring

### 3.1 NSA Kubernetes Hardening Framework

| Framework | Score | Compliance | Status |
|-----------|-------|------------|--------|
| **NSA Framework** | 39.01% | 53.9% | ❌ FAIL |

### 3.2 Control Breakdown

| Control Category | Passed | Failed | Skipped | Score |
|------------------|--------|--------|---------|-------|
| **Access Control** | 2 | 0 | 0 | 100% |
| **Control Plane** | 1 | 0 | 4 | 100% (limited) |
| **Secrets** | 1 | 1 | 0 | 50% |
| **Workload** | 0 | 6 | 0 | 0% |
| **Network** | 2 | 1 | 0 | 67% |
| **Resource Management** | 0 | 2 | 0 | 0% |

### 3.3 CIS Kubernetes Benchmark (Node)

| Section | Pass | Fail | Warn | Status |
|---------|------|------|------|--------|
| **4.1 Worker Node Configuration Files** | 1 | 5 | 4 | ❌ FAIL |
| **4.2 Kubelet** | 0 | 5 | 10 | ❌ FAIL |
| **4.3 kube-proxy** | 0 | 1 | 0 | ❌ FAIL |
| **Total** | 1 | 11 | 14 | ❌ FAIL |

### 3.4 Popeye Audit Score

| Component | Score | Grade | Status |
|-----------|-------|-------|--------|
| **Overall** | 80/100 | B | ⚠️ WARNING |
| **Deployments** | 0/100 | F | ❌ FAIL |
| **Pods** | 0/100 | F | ❌ FAIL |
| **Services** | 11/100 | F | ❌ FAIL |
| **Jobs** | 0/100 | F | ❌ FAIL |
| **ConfigMaps** | 100/100 | A | ✅ PASS |
| **Secrets** | 100/100 | A | ✅ PASS |

---

## 4. Port Scan Results

### 4.1 Open Ports on Worker Node

| Port | Service Name | Status | Notes |
|------|--------------|--------|-------|
| 22 | SSH | ✅ Open | Standard SSH access |
| 2376 | Docker | ⚠️ Open | Docker daemon API (should be restricted) |
| 2379 | etcd-client | ⚠️ Open | etcd client port |
| 2381 | compaq-https | ⚠️ Open | Unknown service |
| 8443 | https-alt | ⚠️ Open | HTTPS alternative port |
| 10248 | - | ⚠️ Open | Kubelet health check port |
| 10249 | - | ⚠️ Open | kube-proxy metrics |
| 10250 | - | ⚠️ Open | Kubelet API (should be secured) |
| 10256 | - | ⚠️ Open | kube-proxy health check |
| 10257 | - | ⚠️ Open | kube-controller-manager |
| 10259 | - | ⚠️ Open | kube-scheduler |
| 34141 | - | ⚠️ Open | Unknown service |

### 4.2 Security Concerns

- **Port 2376 (Docker):** Exposed Docker API without authentication
- **Port 10250 (Kubelet):** Kubelet API exposed (should require authentication)
- **Port 2379 (etcd):** etcd client port exposed
- **Multiple unknown ports:** Ports 2381, 34141 require investigation

---

## 5. Detected Security Issues Summary

### 5.1 Critical Issues

1. **RBAC Privilege Escalation** - Cluster admins can escalate privileges via impersonation
2. **RBAC Admission Controller Modification** - Unauthorized modification of admission controllers possible
3. **Node Proxy Creation** - Ability to create node proxies for Kubelet access
4. **Privileged Containers** - 2 containers running with full host privileges

### 5.2 High Severity Issues

1. **Host PID/IPC Access** - Containers sharing host process/IPC namespace
2. **Missing Resource Limits** - Containers without CPU/memory limits
3. **Secret Access** - Multiple service accounts with excessive secret read permissions
4. **Workload Modification** - Service accounts with broad workload creation/modification rights
5. **Network Policy Absence** - No NetworkPolicies protecting pod ingress/egress
6. **Kubelet Security** - Multiple CIS benchmark failures for kubelet configuration

### 5.3 Medium Severity Issues

1. **Non-root Containers** - All containers running as root user
2. **Privilege Escalation** - Containers allowing privilege escalation
3. **Service Account Auto-mount** - Automatic service account token mounting enabled
4. **Missing Health Probes** - Containers without liveness/readiness probes
5. **Untagged Images** - Multiple containers using untagged Docker images

---

## 6. Remediation Guidance

### 6.1 Critical Priority Remediations

#### Issue: RBAC Privilege Escalation via Impersonation
**What is insecure:** The `kubeadm:cluster-admins` group has permissions to impersonate any user or service account, allowing privilege escalation.

**Why it matters:** An attacker with cluster-admin access can impersonate any service account or user, bypassing all RBAC controls.

**How to fix:**
1. Review and restrict impersonation permissions:
   ```bash
   kubectl get clusterrole cluster-admin -o yaml
   ```
2. Remove or restrict the `impersonate` verb from cluster-admin role
3. Create separate roles for legitimate impersonation needs
4. Use Kubernetes audit logging to monitor impersonation attempts

#### Issue: Privileged Containers
**What is insecure:** Containers `system-monitor-deployment` and `health-check-deployment` are running with `privileged: true`, giving them full host access.

**Why it matters:** Privileged containers can escape to the host, access host resources, and compromise the entire node.

**How to fix:**
1. Remove `privileged: true` from container securityContext:
   ```yaml
   securityContext:
     privileged: false
   ```
2. Use specific capabilities instead of privileged mode:
   ```yaml
   securityContext:
     capabilities:
       add: ["SYS_ADMIN"]  # Only if absolutely necessary
   ```
3. For `system-monitor-deployment`, consider using read-only host mounts or sidecar containers
4. For `health-check-deployment`, remove privileged access and use proper health check endpoints

#### Issue: Host PID/IPC Namespace Sharing
**What is insecure:** `system-monitor-deployment` uses `hostPID: true` and `hostIPC: true`, sharing host process and IPC namespaces.

**Why it matters:** Containers can see and interact with host processes, potentially accessing sensitive information or interfering with host operations.

**How to fix:**
1. Remove host namespace sharing:
   ```yaml
   spec:
     template:
       spec:
         hostPID: false
         hostIPC: false
   ```
2. If monitoring is required, use read-only host mounts or proper monitoring tools
3. Consider using DaemonSets with proper security contexts instead

### 6.2 High Priority Remediations

#### Issue: Missing Network Policies
**What is insecure:** All pods lack NetworkPolicy protection, allowing unrestricted ingress and egress traffic.

**Why it matters:** Without NetworkPolicies, compromised pods can communicate with any other pod or external service, facilitating lateral movement.

**How to fix:**
1. Create NetworkPolicies for each deployment:
   ```yaml
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: default-deny-all
     namespace: default
   spec:
     podSelector: {}
     policyTypes:
     - Ingress
     - Egress
   ```
2. Create allow policies for specific applications:
   ```yaml
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: allow-app-specific
   spec:
     podSelector:
       matchLabels:
         app: your-app
     policyTypes:
     - Ingress
     - Egress
     ingress:
     - from:
       - podSelector:
           matchLabels:
             app: allowed-client
       ports:
       - protocol: TCP
         port: 3000
     egress:
     - to:
       - podSelector:
           matchLabels:
             app: database
       ports:
       - protocol: TCP
         port: 5432
   ```

#### Issue: Containers Running as Root
**What is insecure:** All 8 containers are running as root user (UID 0).

**Why it matters:** If a container is compromised, the attacker has root privileges, increasing the risk of container escape or host compromise.

**How to fix:**
1. Add security context to all containers:
   ```yaml
   securityContext:
     runAsNonRoot: true
     runAsUser: 1000
     runAsGroup: 1000
     allowPrivilegeEscalation: false
   ```
2. Ensure container images support non-root users
3. Create a non-root user in Dockerfiles:
   ```dockerfile
   RUN groupadd -r appuser && useradd -r -g appuser appuser
   USER appuser
   ```

#### Issue: Missing Resource Limits
**What is insecure:** `batch-check-job` container lacks CPU and memory limits.

**Why it matters:** Containers without limits can consume all available node resources, causing DoS or affecting other workloads.

**How to fix:**
1. Add resource limits to all containers:
   ```yaml
   resources:
     requests:
       cpu: "100m"
       memory: "128Mi"
     limits:
       cpu: "500m"
       memory: "512Mi"
   ```
2. Use ResourceQuotas at namespace level to enforce limits
3. Monitor resource usage and adjust limits accordingly

#### Issue: Kubelet Security Configuration
**What is insecure:** Multiple CIS benchmark failures for kubelet configuration, including anonymous authentication and missing client CA file.

**Why it matters:** Insecure kubelet configuration allows unauthorized access to node resources and pod information.

**How to fix:**
1. Configure kubelet with proper authentication:
   ```bash
   # Edit /etc/systemd/system/kubelet.service.d/10-kubeadm.conf
   # Add to KUBELET_SYSTEM_PODS_ARGS:
   --anonymous-auth=false
   --authorization-mode=Webhook
   --client-ca-file=/etc/kubernetes/pki/ca.crt
   ```
2. Set proper file permissions:
   ```bash
   chmod 600 /etc/kubernetes/kubelet.conf
   chown root:root /etc/kubernetes/kubelet.conf
   chmod 600 /var/lib/kubelet/config.yaml
   chown root:root /var/lib/kubelet/config.yaml
   ```
3. Restart kubelet service:
   ```bash
   systemctl daemon-reload
   systemctl restart kubelet
   ```

### 6.3 Medium Priority Remediations

#### Issue: Automatic Service Account Token Mounting
**What is insecure:** 9 out of 10 resources automatically mount service account tokens.

**Why it matters:** Unnecessary service account tokens increase attack surface if a container is compromised.

**How to fix:**
1. Disable auto-mounting at pod level:
   ```yaml
   spec:
     automountServiceAccountToken: false
   ```
2. Disable at service account level:
   ```yaml
   apiVersion: v1
   kind: ServiceAccount
   metadata:
     name: my-service-account
   automountServiceAccountToken: false
   ```
3. Only enable for pods that actually need API access

#### Issue: Missing Health Probes
**What is insecure:** Multiple containers lack liveness and readiness probes.

**Why it matters:** Without health probes, Kubernetes cannot detect unhealthy containers and restart them automatically.

**How to fix:**
1. Add health probes to all containers:
   ```yaml
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
   ```
2. Use appropriate probe types (httpGet, tcpSocket, exec)
3. Set appropriate timeouts and thresholds

#### Issue: Untagged Docker Images
**What is insecure:** Multiple containers use untagged Docker images (e.g., `madhuakula/k8s-goat-build-code`).

**Why it matters:** Untagged images default to `latest`, which can change unexpectedly and cause deployment issues or security vulnerabilities.

**How to fix:**
1. Always use specific image tags:
   ```yaml
   image: madhuakula/k8s-goat-build-code:v1.2.3
   ```
2. Use image pull policies:
   ```yaml
   imagePullPolicy: IfNotPresent  # or Always
   ```
3. Implement image scanning in CI/CD pipeline
4. Use image digests for maximum security:
   ```yaml
   image: madhuakula/k8s-goat-build-code@sha256:abc123...
   ```

#### Issue: Immutable Container Filesystem
**What is insecure:** All containers have writable root filesystems.

**Why it matters:** Writable filesystems allow attackers to modify application files, install malware, or tamper with logs.

**How to fix:**
1. Enable read-only root filesystem:
   ```yaml
   securityContext:
     readOnlyRootFilesystem: true
   ```
2. Mount writable volumes for necessary directories:
   ```yaml
   volumeMounts:
   - name: tmp
     mountPath: /tmp
   - name: var-run
     mountPath: /var/run
   volumes:
   - name: tmp
     emptyDir: {}
   - name: var-run
     emptyDir: {}
   ```

### 6.4 Port Security Remediations

#### Issue: Exposed Docker API (Port 2376)
**What is insecure:** Docker daemon API exposed on port 2376 without authentication.

**Why it matters:** Unauthorized access to Docker API allows container manipulation, image pulling, and potential host compromise.

**How to fix:**
1. Restrict Docker API access to localhost only
2. Enable TLS authentication for Docker daemon
3. Use firewall rules to block external access
4. Consider using containerd instead of Docker

#### Issue: Exposed Kubelet API (Port 10250)
**What is insecure:** Kubelet API exposed without proper authentication.

**Why it matters:** Unauthorized access to Kubelet API allows pod manipulation and information disclosure.

**How to fix:**
1. Configure kubelet with authentication (see Kubelet Security Configuration above)
2. Use NetworkPolicies to restrict access
3. Enable kubelet authentication webhook
4. Monitor kubelet API access logs

---

## 7. Recommendations Priority Matrix

| Priority | Issue | Impact | Effort | Timeline |
|----------|-------|--------|--------|----------|
| **P0 - Immediate** | RBAC Privilege Escalation | Critical | Medium | 1-2 days |
| **P0 - Immediate** | Privileged Containers | Critical | Low | 1 day |
| **P0 - Immediate** | Host PID/IPC Access | Critical | Low | 1 day |
| **P1 - High** | Network Policies | High | Medium | 3-5 days |
| **P1 - High** | Non-root Containers | High | Medium | 1 week |
| **P1 - High** | Resource Limits | High | Low | 2-3 days |
| **P1 - High** | Kubelet Security | High | Medium | 3-5 days |
| **P2 - Medium** | Service Account Auto-mount | Medium | Low | 2-3 days |
| **P2 - Medium** | Health Probes | Medium | Low | 3-5 days |
| **P2 - Medium** | Image Tagging | Medium | Low | 1 week |
| **P3 - Low** | Read-only Filesystem | Low | Medium | 2 weeks |

---

## 8. Compliance Status Summary

| Framework | Score | Status | Notes |
|-----------|-------|--------|-------|
| **NSA Kubernetes Hardening** | 53.9% | ❌ FAIL | Multiple critical controls failed |
| **CIS Kubernetes Benchmark** | ~8% | ❌ FAIL | 11 failures, 14 warnings |
| **Popeye Audit** | 80% | ⚠️ WARNING | Grade B, multiple issues detected |

---

## 9. Next Steps

1. **Immediate Actions (Week 1):**
   - Fix RBAC privilege escalation issues
   - Remove privileged containers
   - Disable host PID/IPC sharing
   - Implement basic NetworkPolicies

2. **Short-term Actions (Weeks 2-4):**
   - Configure all containers to run as non-root
   - Add resource limits to all containers
   - Fix kubelet security configuration
   - Implement comprehensive NetworkPolicies

3. **Long-term Actions (Months 2-3):**
   - Implement Pod Security Standards
   - Enable Pod Security Admission
   - Set up continuous security scanning
   - Implement security policies using OPA/Kyverno
   - Regular security audits and penetration testing

---

## Appendix A: Tools Used

- **Kubescape v3.0.47** - NSA Kubernetes Hardening Framework scanning
- **Popeye** - Kubernetes resource linting and best practices
- **RBAC-Tool** - RBAC policy analysis
- **kube-bench** - CIS Kubernetes Benchmark compliance checking
- **Nmap 7.98** - Port scanning and service detection

---

## Appendix B: Scan Metadata

- **Scan Date:** January 28, 2026
- **Kubernetes Version:** v1.34.0
- **Namespace Scanned:** default
- **Worker Nodes:** 1
- **Total Resources Scanned:** 12

---

**Report Generated By:** Kubernetes Security Assessment Tool  
**For Questions or Concerns:** Please contact your security team
