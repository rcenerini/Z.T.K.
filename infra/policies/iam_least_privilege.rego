# policy: iam_least_privilege.rego
# Valida que politicas IAM seguem o principio de menor privilegio.
# Aplicado em terraform plan (pre-deploy) e CI/CD.
#
# Regras:
# 1. Nenhuma policy pode conter "Resource": "*" + "Action": "*"
# 2. Nenhuma policy pode conter "Effect": "Allow" com wildcard duplo
# 3. Roles de servico devem ter condicoes de uso

package ztk.iam_least_privilege

import rego.v1

# ── Violations ────────────────────────────────────────────────────

# Violacao: Allow + Resource:* + Action:* (superadmin implicito)
violation contains msg if {
    policy := input.iam_policies[_]
    statement := policy.Statement[_]
    statement.Effect == "Allow"
    statement.Resource[_] == "*"
    statement.Action[_] == "*"
    msg := sprintf("CRITICAL: policy '%s' grants unrestricted access (Allow + Resource:* + Action:*)", [policy.PolicyName])
}

# Violacao: Resource:* sem condicao restrictiva
violation contains msg if {
    policy := input.iam_policies[_]
    statement := policy.Statement[_]
    statement.Effect == "Allow"
    statement.Resource[_] == "*"
    not statement.Condition
    msg := sprintf("HIGH: policy '%s' uses Resource:* without any condition restriction", [policy.PolicyName])
}

# Violacao: Action inclui permissoes de administracao perigosas
dangerous_actions := {
    "iam:*",
    "iam:Create*",
    "iam:Delete*",
    "iam:Put*",
    "iam:Update*",
    "iam:Attach*",
    "iam:Detach*",
    "kms:Delete*",
    "kms:Disable*",
    "s3:DeleteBucket",
    "dynamodb:DeleteTable",
}

violation contains msg if {
    policy := input.iam_policies[_]
    statement := policy.Statement[_]
    statement.Effect == "Allow"
    action := statement.Action[_]
    dangerous_actions[action]
    msg := sprintf("CRITICAL: policy '%s' grants dangerous action '%s'", [policy.PolicyName, action])
}

# Violacao: KMS key sem rotacao habilitada
violation contains msg if {
    key := input.kms_keys[_]
    not key.enable_key_rotation
    msg := sprintf("HIGH: KMS key '%s' does not have key rotation enabled", [key.key_id])
}

# Violacao: S3 bucket sem block public access
violation contains msg if {
    bucket := input.s3_buckets[_]
    not bucket.block_public_access
    msg := sprintf("CRITICAL: S3 bucket '%s' does not block public access", [bucket.name])
}

# Violacao: DynamoDB table sem PITR
violation contains msg if {
    table := input.dynamodb_tables[_]
    not table.point_in_time_recovery
    msg := sprintf("HIGH: DynamoDB table '%s' does not have PITR enabled (PCI DSS 10.7)", [table.name])
}

# Violacao: DynamoDB table sem encryption
violation contains msg if {
    table := input.dynamodb_tables[_]
    not table.encryption_enabled
    msg := sprintf("HIGH: DynamoDB table '%s' does not have encryption enabled (PCI DSS 3.4)", [table.name])
}

# ── Default (no violations = compliant) ───────────────────────────

default compliant := false

compliant if {
    count(violation) == 0
}
