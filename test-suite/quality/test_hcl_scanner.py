"""Independent, bounded Terraform/AWS oracle for beads mj1j.35/.36.

Labels are source-configuration claims, not deployed AWS reachability claims.
The initial oracle and unsupported-language baseline precede hcl_scan.py.
Authoritative semantics used to choose these cases:
https://github.com/hashicorp/terraform-provider-aws/blob/main/website/docs/r/vpc_security_group_ingress_rule.html.markdown
https://github.com/hashicorp/terraform-provider-aws/blob/main/website/docs/r/security_group_rule.html.markdown
https://github.com/hashicorp/terraform-provider-aws/blob/main/website/docs/r/security_group.html.markdown
https://github.com/hashicorp/terraform-provider-aws/blob/main/website/docs/r/s3_bucket_public_access_block.html.markdown
https://github.com/hashicorp/terraform-provider-aws/blob/main/website/docs/r/s3_bucket_acl.html.markdown
https://developer.hashicorp.com/terraform/language/files
https://github.com/hashicorp/hcl/blob/main/hclsyntax/spec.md

Only explicit TCP administrative ports (22/3389) or all protocols with a world
CIDR are in the ingress rule's scope. Public web or UDP-only rules are controls.
IgnorePublicAcls neutralizes ACL access; BlockPublicAcls prevents new writes and
does not neutralize existing ACLs. Contradictory/unknown configuration is partial.
Artifacts are intentionally retained: this repository prohibits file deletion.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "modules/helpers"))
RULES = {
    "network": "hcl.aws.public-admin-ingress", "storage": "hcl.aws.public-s3-acl",
    "iam": "hcl.aws.iam-wildcard-privilege", "tls": "hcl.aws.insecure-provider-tls",
}
CATEGORY_IDS = {RULES[name]: number for number, name in enumerate(("network", "storage", "iam", "tls"), 1)}


@dataclass(frozen=True)
class Case:
    name: str
    code: str
    incomplete: bool = False
    locations: tuple[tuple[str, int, int], ...] = ()

    @property
    def source(self):
        return textwrap.dedent(self.code).strip("\n") + "\n"

    @property
    def filename(self):
        return self.name + ".tf"

    @property
    def expected(self):
        result = [(RULES[name], line, col) for name, line, col in self.locations]
        for line, source in enumerate(self.source.splitlines(), 1):
            if "# expect:" in source:
                for name in source.split("# expect:", 1)[1].strip().split(","):
                    result.append((RULES[name], line, len(source) - len(source.lstrip()) + 1))
        return sorted(result)


CASES = (
    Case("public_ssh_ipv4", '''
        resource "aws_vpc_security_group_ingress_rule" "ssh" { # expect:network
          security_group_id = "sg-example"
          cidr_ipv4 = "0.0.0.0/0"
          ip_protocol = "tcp"
          from_port = 22
          to_port = 22
        }
    '''),
    Case("public_rdp_ipv6_numeric_protocol", '''
        resource "aws_vpc_security_group_ingress_rule" "rdp" { # expect:network
          security_group_id = "sg-example"
          cidr_ipv6 = "::/0"
          ip_protocol = "6"
          from_port = 3389
          to_port = 3389
        }
    '''),
    Case("inline_all_protocols", '''
        resource "aws_security_group" "admin" {
          ingress { # expect:network
            protocol = "-1"
            from_port = 0
            to_port = 0
            cidr_blocks = ["0.0.0.0/0"]
            ipv6_cidr_blocks = ["::/0"]
          }
        }
    '''),
    Case("legacy_admin_range", '''
        resource "aws_security_group_rule" "admin" { # expect:network
          type = "ingress"
          security_group_id = "sg-example"
          protocol = "tcp"
          from_port = 20
          to_port = 23
          cidr_blocks = ["10.0.0.0/8", "0.0.0.0/0"]
        }
    '''),
    Case("modern_all_protocols_no_ports", '''
        resource "aws_vpc_security_group_ingress_rule" "all" { # expect:network
          security_group_id = "sg-example"
          cidr_ipv4 = "0.0.0.0/0"
          ip_protocol = "-1"
        }
    '''),
    Case("restricted_admin_network", '''
        resource "aws_vpc_security_group_ingress_rule" "ssh" {
          security_group_id = "sg-example"
          cidr_ipv4 = "10.0.0.0/8"
          ip_protocol = "tcp"
          from_port = 22
          to_port = 22
        }
    '''),
    Case("public_https_control", '''
        resource "aws_vpc_security_group_ingress_rule" "https" {
          security_group_id = "sg-example"
          cidr_ipv4 = "0.0.0.0/0"
          ip_protocol = "tcp"
          from_port = 443
          to_port = 443
        }
    '''),
    Case("udp_is_not_tcp_admin", '''
        resource "aws_vpc_security_group_ingress_rule" "udp" {
          security_group_id = "sg-example"
          cidr_ipv4 = "0.0.0.0/0"
          ip_protocol = "udp"
          from_port = 22
          to_port = 22
        }
    '''),
    Case("egress_is_not_ingress", '''
        resource "aws_security_group_rule" "outbound" {
          type = "egress"
          security_group_id = "sg-example"
          protocol = "-1"
          from_port = 0
          to_port = 0
          cidr_blocks = ["0.0.0.0/0"]
        }
    '''),
    Case("locals_forward_chain", '''
        locals {
          source = local.world
          port = 22
        }
        locals {
          world = "0.0.0.0/0"
        }
        resource "aws_vpc_security_group_ingress_rule" "ssh" { # expect:network
          security_group_id = "sg-example"
          cidr_ipv4 = local.source
          ip_protocol = "tcp"
          from_port = local.port
          to_port = local.port
        }
    '''),
    Case("irrelevant_unknown_tags", '''
        resource "aws_vpc_security_group_ingress_rule" "ssh" { # expect:network
          security_group_id = var.security_group
          cidr_ipv4 = "0.0.0.0/0"
          ip_protocol = "tcp"
          from_port = 22
          to_port = 22
          tags = var.tags
        }
    '''),
    Case("inline_public_bucket_acl", '''
        resource "aws_s3_bucket" "example" {
          bucket = "example-bucket"
          acl = "public-read" # expect:storage
        }
    '''),
    Case("separate_public_bucket_acl", '''
        resource "aws_s3_bucket" "example" {
          bucket = "example-bucket"
        }
        resource "aws_s3_bucket_acl" "example" {
          bucket = aws_s3_bucket.example.id
          acl = "public-read-write" # expect:storage
        }
    '''),
    Case("private_bucket_acl", '''
        resource "aws_s3_bucket" "example" {
          bucket = "example-bucket"
          acl = "private"
        }
    '''),
    Case("ignored_acl_exact_bucket", '''
        resource "aws_s3_bucket" "example" {
          bucket = "example-bucket"
          acl = "public-read"
        }
        resource "aws_s3_bucket_public_access_block" "example" {
          bucket = aws_s3_bucket.example.id
          ignore_public_acls = true
        }
    '''),
    Case("wrong_bucket_protection", '''
        resource "aws_s3_bucket" "exposed" {
          bucket = "exposed-bucket"
          acl = "public-read" # expect:storage
        }
        resource "aws_s3_bucket" "different" {
          bucket = "different-bucket"
        }
        resource "aws_s3_bucket_public_access_block" "different" {
          bucket = aws_s3_bucket.different.id
          ignore_public_acls = true
        }
    '''),
    Case("policy_protection_does_not_protect_acl", '''
        resource "aws_s3_bucket" "example" {
          bucket = "example-bucket"
          acl = "public-read" # expect:storage
        }
        resource "aws_s3_bucket_public_access_block" "example" {
          bucket = aws_s3_bucket.example.id
          block_public_policy = true
          restrict_public_buckets = true
          ignore_public_acls = false
          block_public_acls = false
        }
    '''),
    Case("zero_count_has_no_instance", '''
        resource "aws_s3_bucket" "example" {
          count = 0
          bucket = "example-bucket"
          acl = "public-read"
        }
    '''),
    Case("empty_for_each_has_no_instance", '''
        resource "aws_s3_bucket" "example" {
          for_each = {}
          bucket = "example-bucket"
          acl = "public-read"
        }
    '''),
    Case("comments_strings_and_heredoc_decoys", '''
        # resource "aws_s3_bucket" "comment" { acl = "public-read" }
        /* resource "aws_s3_bucket" "block" { acl = "public-read" } */
        locals {
          quoted = "acl = \\"public-read\\""
          documentation = <<-TEXT
            resource "aws_s3_bucket" "heredoc" {
              acl = "public-read"
            }
          TEXT
        }
        resource "azurerm_storage_account" "not_aws" {
          acl = "public-read"
        }
    '''),
    Case("exact_comment_suppression", '''
        resource "aws_s3_bucket" "example" {
          bucket = "example-bucket"
          acl = "public-read" # ubs:ignore[hcl.aws.public-s3-acl]
        }
    '''),
    Case("string_cannot_suppress", '''
        resource "aws_s3_bucket" "example" {
          bucket = "example-bucket"
          acl = "public-read" # expect:storage
          tags = { note = "# ubs:ignore[hcl.aws.public-s3-acl]" }
        }
    '''),
    Case("unknown_cidr", '''
        resource "aws_vpc_security_group_ingress_rule" "ssh" {
          security_group_id = "sg-example"
          cidr_ipv4 = var.cidr
          ip_protocol = "tcp"
          from_port = 22
          to_port = 22
        }
    ''', True),
    Case("unknown_template_cidr", '''
        resource "aws_vpc_security_group_ingress_rule" "ssh" {
          security_group_id = "sg-example"
          cidr_ipv4 = "${var.prefix}/0"
          ip_protocol = "tcp"
          from_port = 22
          to_port = 22
        }
    ''', True),
    Case("unknown_replication", '''
        resource "aws_s3_bucket" "example" {
          count = var.enabled ? 1 : 0
          bucket = "example-bucket"
          acl = "public-read"
        }
    ''', True),
    Case("dynamic_ingress", '''
        resource "aws_security_group" "example" {
          dynamic "ingress" {
            for_each = var.rules
            content {
              protocol = "tcp"
              from_port = 22
              to_port = 22
              cidr_blocks = ingress.value.cidrs
            }
          }
        }
    ''', True),
    Case("block_acl_conflict", '''
        resource "aws_s3_bucket" "example" {
          bucket = "example-bucket"
          acl = "public-read"
        }
        resource "aws_s3_bucket_public_access_block" "example" {
          bucket = aws_s3_bucket.example.id
          block_public_acls = true
        }
    ''', True),
    Case("unknown_acl_protection", '''
        resource "aws_s3_bucket" "example" {
          bucket = "example-bucket"
          acl = "public-read"
        }
        resource "aws_s3_bucket_public_access_block" "example" {
          bucket = aws_s3_bucket.example.id
          ignore_public_acls = var.ignore_public
        }
    ''', True),
    Case("ownership_enforced_conflict", '''
        resource "aws_s3_bucket" "example" {
          bucket = "example-bucket"
        }
        resource "aws_s3_bucket_acl" "example" {
          bucket = aws_s3_bucket.example.id
          acl = "public-read"
        }
        resource "aws_s3_bucket_ownership_controls" "example" {
          bucket = aws_s3_bucket.example.id
          rule {
            object_ownership = "BucketOwnerEnforced"
          }
        }
    ''', True),
    Case("rebound_aws_provider", '''
        terraform {
          required_providers {
            aws = {
              source = "example/not-aws"
            }
          }
        }
        resource "aws_s3_bucket" "example" {
          bucket = "example-bucket"
          acl = "public-read"
        }
    ''', True),
    Case("cyclic_locals", '''
        locals {
          acl = local.loop
          loop = local.acl
        }
        resource "aws_s3_bucket" "example" {
          bucket = "example-bucket"
          acl = local.acl
        }
    ''', True),
    Case("unterminated_block", '''
        resource "aws_s3_bucket" "example" {
          bucket = "example-bucket"
          acl = "public-read"
    ''', True),
    Case("unterminated_string", '''
        resource "aws_s3_bucket" "example" {
          bucket = "example-bucket"
          acl = "public-read
        }
    ''', True),
)


# Independent adversarial review additions. These preserve the original oracle
# above; pre-fix reproductions are retained under test-suite/artifacts/hcl/review*.
# Provider CIDR validators use net.ParseCIDR and require a network address:
# https://github.com/hashicorp/terraform-provider-aws/blob/main/internal/types/cidr_block.go
# Terraform coerces number literals to provider string/int argument types:
# https://developer.hashicorp.com/terraform/language/expressions/types
REVIEW_CASES = (
    Case("competing_public_access_controls", '''
        resource "aws_s3_bucket" "example" {
          bucket = "example-bucket"
          acl = "public-read"
        }
        resource "aws_s3_bucket_public_access_block" "on" {
          bucket = aws_s3_bucket.example.id
          ignore_public_acls = true
        }
        resource "aws_s3_bucket_public_access_block" "off" {
          bucket = aws_s3_bucket.example.id
          ignore_public_acls = false
        }
    ''', True),
    Case("duplicate_public_access_control_address", '''
        resource "aws_s3_bucket" "example" {
          bucket = "example-bucket"
          acl = "public-read"
        }
        resource "aws_s3_bucket_public_access_block" "same" {
          bucket = aws_s3_bucket.example.id
          ignore_public_acls = true
        }
        resource "aws_s3_bucket_public_access_block" "same" {
          bucket = aws_s3_bucket.example.id
          ignore_public_acls = false
        }
    ''', True),
    Case("decimal_tcp_protocol", '''
        resource "aws_vpc_security_group_ingress_rule" "admin" { # expect:network
          security_group_id = "sg-example"
          cidr_ipv4 = "0.0.0.0/0"
          ip_protocol = 6.0
          from_port = 22
          to_port = 22
        }
    '''),
    Case("decimal_all_protocols", '''
        resource "aws_vpc_security_group_ingress_rule" "admin" { # expect:network
          security_group_id = "sg-example"
          cidr_ipv4 = "0.0.0.0/0"
          ip_protocol = -1.0
        }
    '''),
    Case("nested_local_object_public_acl", '''
        locals {
          settings = {
            bucket = {
              acl = "public-read"
              note = "documentation"
            }
          }
        }
        resource "aws_s3_bucket" "example" {
          bucket = "example-bucket"
          acl = local.settings.bucket.acl # expect:storage
        }
    '''),
    Case("nested_local_object_private_acl", '''
        locals {
          settings = {
            bucket = {
              acl = "private"
              note = "documentation"
            }
          }
        }
        resource "aws_s3_bucket" "example" {
          bucket = "example-bucket"
          acl = local.settings.bucket.acl
        }
    '''),
    Case("inactive_unresolved_control_cannot_protect", '''
        resource "aws_s3_bucket" "example" {
          bucket = "example-bucket"
          acl = "public-read" # expect:storage
        }
        resource "aws_s3_bucket_public_access_block" "absent" {
          count = 0
          bucket = var.bucket
          ignore_public_acls = true
        }
    '''),
    Case("boolean_protocol_is_invalid", '''
        resource "aws_vpc_security_group_ingress_rule" "admin" {
          security_group_id = "sg-example"
          cidr_ipv4 = "0.0.0.0/0"
          ip_protocol = true
          from_port = 22
          to_port = 22
        }
    ''', True),
    Case("dotted_network_mask_is_not_cidr", '''
        resource "aws_vpc_security_group_ingress_rule" "admin" {
          security_group_id = "sg-example"
          cidr_ipv4 = "0.0.0.0/0.0.0.0"
          ip_protocol = "tcp"
          from_port = 22
          to_port = 22
        }
    ''', True),
    Case("non_network_cidr_is_rejected_by_provider", '''
        resource "aws_vpc_security_group_ingress_rule" "admin" {
          security_group_id = "sg-example"
          cidr_ipv4 = "0.0.0.1/0"
          ip_protocol = "tcp"
          from_port = 22
          to_port = 22
        }
    ''', True),
    Case("trailing_marker_does_not_suppress_next_attribute", '''
        resource "aws_s3_bucket" "example" {
          bucket = "example-bucket" # ubs:ignore[hcl.aws.public-s3-acl]
          acl = "public-read" # expect:storage
        }
    '''),
    Case("formatter_relocated_block_marker", '''
        resource "aws_vpc_security_group_ingress_rule" "admin" {
          # ubs:ignore[hcl.aws.public-admin-ingress]
          security_group_id = "sg-example"
          cidr_ipv4 = "0.0.0.0/0"
          ip_protocol = "tcp"
          from_port = 22
          to_port = 22
        }
    '''),
    Case("inline_ingress_header_marker", '''
        resource "aws_vpc_security_group_ingress_rule" "admin" { # ubs:ignore[hcl.aws.public-admin-ingress]
          security_group_id = "sg-example"
          cidr_ipv4 = "0.0.0.0/0"
          ip_protocol = "tcp"
          from_port = 22
          to_port = 22
        }
    '''),
    Case("duplicate_provider_requirements_are_unknown", '''
        terraform {
          required_providers {
            aws = { source = "different/aws" }
          }
        }
        terraform {
          required_providers {
            aws = { source = "hashicorp/aws" }
          }
        }
        resource "aws_s3_bucket" "example" {
          bucket = "example-bucket"
          acl = "public-read"
        }
        resource "aws_s3_bucket_public_access_block" "protected" {
          bucket = aws_s3_bucket.example.id
          ignore_public_acls = true
        }
    ''', True),
)


# Second independently specified slice: exact wildcard identity-policy intent
# and an explicitly insecure HashiCorp AWS provider. Effective deployed access,
# policy attachment, permissions boundaries, SCPs and trust policies are outside
# this rule. AWS explicit Deny and conditions must not be mistaken for an
# unconditional grant; unsupported policy interactions stay incomplete.
# https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html
# https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
# https://developer.hashicorp.com/terraform/language/functions/jsonencode
# https://github.com/hashicorp/terraform-provider-aws/blob/main/website/docs/index.html.markdown
IAM_CASES = (
    Case("iam_literal_json_heredoc", '''
        resource "aws_iam_policy" "admin" {
          policy = <<POLICY
        {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}
        POLICY
        }
    ''', locations=(("iam", 2, 3),)),
    Case("iam_jsonencode_wildcard_arrays", '''
        resource "aws_iam_policy" "array_admin" {
          policy = jsonencode({ # expect:iam
            Version = "2012-10-17"
            Statement = [{
              Effect = "Allow"
              Action = ["s3:GetObject", "*"]
              Resource = ["arn:aws:s3:::example/*", "*"]
            }]
          })
        }
    '''),
    Case("iam_local_object_policy", '''
        locals {
          permission = {
            Effect = "Allow"
            Action = "*"
            Resource = "*"
          }
          document = {
            Version = "2012-10-17"
            Statement = [local.permission]
          }
        }
        resource "aws_iam_role_policy" "inline_admin" {
          role = var.role_name
          policy = jsonencode(local.document) # expect:iam
        }
    '''),
    Case("iam_quoted_json_user_policy", r'''
        resource "aws_iam_user_policy" "user_admin" {
          user = "example-user"
          policy = "{\"Statement\":{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}}" # expect:iam
        }
    '''),
    Case("iam_group_policy_single_statement", '''
        resource "aws_iam_group_policy" "group_admin" {
          group = "example-group"
          policy = jsonencode({ # expect:iam
            Statement = { Effect = "Allow", Action = "*", Resource = "*" }
          })
        }
    '''),
    Case("iam_restricted_actions_are_not_administrator", '''
        resource "aws_iam_policy" "readonly" {
          policy = jsonencode({
            Statement = [{ Effect = "Allow", Action = ["ec2:Describe*", "s3:GetObject"], Resource = "*" }]
          })
        }
    '''),
    Case("iam_restricted_resources", '''
        resource "aws_iam_policy" "bucket_only" {
          policy = jsonencode({
            Statement = [{ Effect = "Allow", Action = "*", Resource = "arn:aws:s3:::example/*" }]
          })
        }
    '''),
    Case("iam_deny_does_not_grant", '''
        resource "aws_iam_policy" "deny_only" {
          policy = jsonencode({
            Statement = [{ Effect = "Deny", Action = "*", Resource = "*" }]
          })
        }
    '''),
    Case("iam_allow_with_deny_is_incomplete", '''
        resource "aws_iam_policy" "with_deny" {
          policy = jsonencode({
            Statement = [
              { Effect = "Allow", Action = "*", Resource = "*" },
              { Effect = "Deny", Action = "*", Resource = "*" },
            ]
          })
        }
    ''', True),
    Case("iam_conditional_allow_is_incomplete", '''
        resource "aws_iam_policy" "conditional_admin" {
          policy = jsonencode({
            Statement = [{
              Effect = "Allow"
              Action = "*"
              Resource = "*"
              Condition = { IpAddress = { "aws:SourceIp" = "10.0.0.0/8" } }
            }]
          })
        }
    ''', True),
    Case("iam_not_action_is_outside_selected_model", '''
        resource "aws_iam_policy" "not_action" {
          policy = jsonencode({
            Statement = [{ Effect = "Allow", NotAction = "iam:*", Resource = "*" }]
          })
        }
    ''', True),
    Case("iam_duplicate_json_keys_are_invalid", '''
        resource "aws_iam_policy" "duplicate_effect" {
          policy = <<POLICY
        {"Statement":[{"Effect":"Deny","Effect":"Allow","Action":"*","Resource":"*"}]}
        POLICY
        }
    ''', True),
    Case("iam_principal_invalid_in_identity_policy", '''
        resource "aws_iam_policy" "invalid_principal" {
          policy = jsonencode({
            Statement = [{ Effect = "Allow", Action = "*", Resource = "*", Principal = "*" }]
          })
        }
    ''', True),
    Case("iam_invalid_action_type", '''
        resource "aws_iam_policy" "invalid_action" {
          policy = jsonencode({
            Statement = [{ Effect = "Allow", Action = ["*", true], Resource = "*" }]
          })
        }
    ''', True),
    Case("iam_policy_attribute_requires_json_string", '''
        resource "aws_iam_policy" "object_without_jsonencode" {
          policy = { Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] }
        }
    ''', True),
    Case("iam_malformed_json_is_partial", '''
        resource "aws_iam_policy" "malformed" {
          policy = <<POLICY
        {"Statement":[{"Effect":"Allow","Action":"*","Resource":"*",}]}
        POLICY
        }
    ''', True),
    Case("iam_unknown_variable_policy", '''
        resource "aws_iam_policy" "variable_document" {
          policy = var.policy_json
        }
    ''', True),
    Case("iam_policy_document_reference_is_not_guessed", '''
        data "aws_iam_policy_document" "example" {
          statement {
            effect = "Allow"
            actions = ["*"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "from_data" {
          policy = data.aws_iam_policy_document.example.json
        }
    ''', True),
    Case("iam_unknown_jsonencode_member", '''
        resource "aws_iam_policy" "unknown_action" {
          policy = jsonencode({
            Statement = [{ Effect = "Allow", Action = var.actions, Resource = "*" }]
          })
        }
    ''', True),
    Case("iam_inactive_unknown_policy_is_not_evaluated", '''
        resource "aws_iam_policy" "disabled" {
          count = 0
          policy = var.policy_json
        }
    '''),
    Case("iam_provider_rebinding_is_unknown", '''
        terraform {
          required_providers {
            aws = { source = "example/not-aws" }
          }
        }
        resource "aws_iam_policy" "unverified_provider" {
          policy = jsonencode({
            Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
          })
        }
    ''', True),
    Case("iam_selected_comment_suppression", '''
        resource "aws_iam_policy" "suppressed_admin" {
          policy = jsonencode({ # ubs:ignore[hcl.aws.iam-wildcard-privilege]
            Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
          })
        }
    '''),
    Case("iam_unrelated_resource_policy_is_not_identity_policy", '''
        resource "aws_s3_bucket_policy" "out_of_scope" {
          bucket = "example-bucket"
          policy = jsonencode({
            Statement = [{ Effect = "Allow", Action = "*", Resource = "*", Principal = "*" }]
          })
        }
        locals {
          documentation = "Effect Allow Action * Resource *"
        }
        # resource "aws_iam_policy" "decoy" { policy = "*" }
    '''),
    Case("iam_empty_optional_sid_does_not_restrict_permissions", '''
        resource "aws_iam_policy" "empty_sid_admin" {
          policy = jsonencode({ # expect:iam
            Statement = [{ Sid = "", Effect = "Allow", Action = "*", Resource = "*" }]
          })
        }
    '''),
)


TLS_CASES = (
    Case("aws_provider_insecure_tls", '''
        provider "aws" {
          insecure = true # expect:tls
        }
    '''),
    Case("aws_provider_renamed_local_binding", '''
        terraform {
          required_providers {
            cloud = { source = "hashicorp/aws" }
          }
        }
        provider "cloud" {
          alias = "secondary"
          insecure = true # expect:tls
        }
    '''),
    Case("aws_provider_local_insecure_value", '''
        locals {
          skip_verification = true
        }
        provider "aws" {
          insecure = local.skip_verification # expect:tls
        }
    '''),
    Case("aws_provider_string_true_coerces_to_boolean", '''
        provider "aws" {
          insecure = "true" # expect:tls
        }
    '''),
    Case("aws_provider_string_false_coerces_to_boolean", '''
        provider "aws" {
          insecure = "false"
        }
    '''),
    Case("aws_provider_false_and_default_tls", '''
        provider "aws" {
          insecure = false
        }
        provider "aws" {
          alias = "default_tls"
          region = "us-east-1"
        }
    '''),
    Case("foreign_provider_insecure_is_not_aws", '''
        terraform {
          required_providers {
            aws = { source = "example/not-aws" }
          }
        }
        provider "aws" {
          insecure = true
        }
    '''),
    Case("aws_provider_insecure_unknown", '''
        provider "aws" {
          insecure = var.skip_verification
        }
    ''', True),
    Case("aws_provider_unresolved_source", '''
        terraform {
          required_providers {
            aws = { source = var.provider_source }
          }
        }
        provider "aws" {
          insecure = true
        }
    ''', True),
    Case("aws_provider_invalid_boolean", '''
        provider "aws" {
          insecure = "sometimes"
        }
    ''', True),
    Case("aws_provider_duplicate_alias_unknown", '''
        provider "aws" {
          alias = "same"
          insecure = true
        }
        provider "aws" {
          alias = "same"
          insecure = false
        }
    ''', True),
    Case("aws_provider_selected_comment_suppression", '''
        provider "aws" {
          alias = "suppressed_tls"
          insecure = true # ubs:ignore[hcl.aws.insecure-provider-tls]
        }
    '''),
    Case("aws_provider_null_uses_default_tls_verification", '''
        locals {
          default_tls = null
        }
        provider "aws" {
          insecure = null
        }
        provider "aws" {
          alias = "local_default"
          insecure = local.default_tls
        }
    '''),
)


class EvidenceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifact = ROOT / "test-suite/artifacts/hcl" / (cls.__name__ + "-" + uuid.uuid4().hex[:12])
        cls.artifact.mkdir(parents=True)
        cls.identity = {"python": sys.version, "oracle_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}

    def setUp(self):
        self.started = time.monotonic()
        print(f"[{self.id()}] RUN evidence={self.artifact}", flush=True)

    def tearDown(self):
        print(f"[{self.id()}] END ({time.monotonic() - self.started:.3f}s)", flush=True)

    def materialize(self, cases, name):
        directory = self.artifact / name
        directory.mkdir()
        for case in cases:
            (directory / case.filename).write_text(case.source, encoding="utf-8")
        return directory


class HCLNativeTests(EvidenceTest):
    def check_native(self, case):
        directory = self.materialize((case,), case.name)
        source = directory / case.filename
        analyzer = importlib.import_module("ubs_core.hcl_scan")
        records, errors = analyzer.analyze_source(case.source, str(source))
        actual = sorted((row["rule"], row["line"], row["col"]) for row in records)
        (directory / "receipt.json").write_text(json.dumps({
            **self.identity, "case": case.name, "expected": case.expected, "actual": actual,
            "findings": records, "errors": errors, "incomplete": case.incomplete,
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "analyzer_sha256": hashlib.sha256(Path(analyzer.__file__).read_bytes()).hexdigest(),
            "elapsed_s": time.monotonic() - self.started,
        }, indent=2) + "\n", encoding="utf-8")
        context = (case.source, records, errors)
        self.assertEqual(bool(errors), case.incomplete, context)
        self.assertEqual(actual, case.expected, context)
        for record in records:
            self.assertEqual(record["severity"], "warning", record)
            self.assertEqual(record["path"], str(source), record)
            self.assertEqual(record["category_id"], CATEGORY_IDS[record["rule"]], record)
            self.assertTrue(record["message"], record)

    def test_selected_module_files_supply_protection_and_locals(self):
        analyzer = importlib.import_module("ubs_core.hcl_scan")
        files = {
            "main.tf": '''resource "aws_s3_bucket" "example" {
  bucket = "example-bucket"
  acl = local.acl
}
''',
            "locals.tf": 'locals { acl = "public-read" }\n',
            "security.tf": '''resource "aws_s3_bucket_public_access_block" "example" {
  bucket = aws_s3_bucket.example.id
  ignore_public_acls = true
}
''',
        }
        directory = self.artifact / "module-context"
        directory.mkdir()
        for name, source in files.items():
            (directory / name).write_text(source, encoding="utf-8")
        paths = {str(directory / name): source for name, source in files.items()}
        records, errors = analyzer.analyze_sources(paths)
        self.assertEqual((records, errors), ([], []))
        records, errors = analyzer.analyze_sources({str(directory / "main.tf"): files["main.tf"]})
        self.assertEqual(records, [])
        self.assertTrue(errors)

    def test_iam_local_expansion_budget_is_incomplete(self):
        # A small source DAG can encode hundreds of MiB. Bound the real helper
        # process as well as requiring an explicit incomplete result, so a
        # missing work/encoding budget cannot hang the acceptance suite.
        declarations = ['  level0 = ["' + "a" * 64 + '"]']
        declarations.extend(f"  level{level} = [local.level{level - 1}, local.level{level - 1}]"
                            for level in range(1, 23))
        code = ("locals {\n" + "\n".join(declarations) + "\n}\n"
                'resource "aws_iam_policy" "expanded" {\n'
                '  policy = jsonencode({\n'
                '    Statement = [{ Effect = "Allow", Action = "*", Resource = "*", Sid = jsonencode(local.level22) }]\n'
                '  })\n}\n')
        case = Case("iam_expansion_budget", code, True)
        directory = self.materialize((case,), case.name)
        source = directory / case.filename
        program = ("import json,sys; from pathlib import Path; "
                   "from ubs_core.hcl_scan import analyze_source; p=Path(sys.argv[1]); "
                   "print(json.dumps(analyze_source(p.read_text(),str(p))))")
        command = [sys.executable, "-c", program, str(source)]
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(ROOT / "modules/helpers"))
        start = time.monotonic()
        try:
            result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=10, check=False)
        except subprocess.TimeoutExpired as exc:
            (directory / "receipt.json").write_text(json.dumps({
                **self.identity, "command": command, "status": "timeout", "elapsed_s": time.monotonic() - start,
                "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            }, indent=2) + "\n", encoding="utf-8")
            self.fail(f"IAM literal expansion exceeded 10-second bound: {exc}")
        (directory / "stdout.log").write_text(result.stdout, encoding="utf-8")
        (directory / "stderr.log").write_text(result.stderr, encoding="utf-8")
        (directory / "receipt.json").write_text(json.dumps({
            **self.identity, "command": command, "exit": result.returncode, "elapsed_s": time.monotonic() - start,
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "analyzer_sha256": hashlib.sha256((ROOT / "modules/helpers/ubs_core/hcl_scan.py").read_bytes()).hexdigest(),
        }, indent=2) + "\n", encoding="utf-8")
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        records, errors = json.loads(result.stdout)
        self.assertEqual(records, [], (records, errors))
        self.assertTrue(errors, "expanded policy must not produce a complete result")


def native_test(case):
    def run(self):
        self.check_native(case)
    return run


for _case in CASES + REVIEW_CASES + IAM_CASES + TLS_CASES:
    setattr(HCLNativeTests, "test_" + _case.name, native_test(_case))


@unittest.skipUnless(os.environ.get("UBS_HCL_E2E") == "1", "set UBS_HCL_E2E=1 for real HCL module/meta-runner acceptance")
class HCLPublicTests(EvidenceTest):
    def execute(self, target, mode="json", extra=(), cached=False):
        attempt = self.artifact / ("command-" + uuid.uuid4().hex[:8])
        attempt.mkdir()
        env = dict(os.environ, UBS_KEEP_TEMP="1", UBS_NO_AUTO_UPDATE="1", UBS_ENABLE_AUTO_UPDATE="0",
                   ENABLE_UV_TOOLS="0", PYTHONDONTWRITEBYTECODE="1", NO_COLOR="1",
                   UBS_NO_CACHE="0" if cached else "1", UBS_CACHE_DIR=str(self.artifact / "cache"),
                   TMPDIR=str(attempt), XDG_CACHE_HOME=str(self.artifact / "xdg-cache"),
                   XDG_CONFIG_HOME=str(self.artifact / "xdg-config"), XDG_DATA_HOME=str(self.artifact / "xdg-data"),
                   XDG_STATE_HOME=str(self.artifact / "xdg-state"))
        script = ROOT / "modules/ubs-hcl.sh" if mode.startswith("module-") else ROOT / "ubs"
        options = [] if mode.startswith("module-") else ["--no-config"]
        command = ["bash", str(script), "--ci", *options, "--fail-on-warning",
                   "--format=" + mode.removeprefix("module-"), *extra, str(target)]
        start = time.monotonic()
        result = subprocess.run(command, cwd=target if target.is_dir() else target.parent,
                                env=env, text=True, capture_output=True, timeout=60, check=False)
        (attempt / "stdout.log").write_text(result.stdout, encoding="utf-8")
        (attempt / "stderr.log").write_text(result.stderr, encoding="utf-8")
        (attempt / "receipt.json").write_text(json.dumps({
            **self.identity, "command": command, "exit": result.returncode,
            "elapsed_s": time.monotonic() - start, "runner_sha256": hashlib.sha256(script.read_bytes()).hexdigest(),
        }, indent=2) + "\n", encoding="utf-8")
        print(f"[hcl-cli:{attempt.name}] exit={result.returncode}", flush=True)
        try:
            return result, json.loads(result.stdout)
        except json.JSONDecodeError:
            self.fail((command, result.returncode, result.stdout, result.stderr))

    def assert_report(self, result, report, mode, cases, *, partial=False, expected_override=None):
        expected = sorted(expected_override) if expected_override is not None else sorted(
            (case.filename, rule, line, col) for case in cases for rule, line, col in case.expected)
        context = (result.returncode, result.stdout, result.stderr)
        self.assertEqual(result.returncode, 2 if partial else int(bool(expected)), context)
        actual = []
        if mode.endswith("sarif"):
            for run in report["runs"]:
                for row in run.get("results", []):
                    location = row["locations"][0]["physicalLocation"]
                    self.assertEqual(row["level"], "warning", context)
                    actual.append((Path(location["artifactLocation"]["uri"]).name, row["ruleId"],
                                   location["region"]["startLine"], location["region"]["startColumn"]))
            if partial:
                self.assertTrue(any(not item["executionSuccessful"] for run in report["runs"]
                                    for item in run.get("invocations", [])), context)
        else:
            totals = report if mode.startswith("module-") else report["totals"]
            self.assertEqual((totals["critical"], totals["warning"], totals["info"], totals["files"]),
                             (0, len(expected), 0, len(cases)), context)
            self.assertEqual(report["status"], "partial" if partial else "ok", context)
            for row in report.get("findings", []):
                self.assertEqual(row["severity"], "warning", context)
                actual.append((Path(row.get("path", row.get("file"))).name, row.get("rule", row.get("rule_id")),
                               row["line"], row["col"]))
        self.assertEqual(sorted(actual), expected, context)

    def test_real_json_sarif_and_autodetection(self):
        # Files share a Terraform module: the clean control needs its own
        # resource address rather than duplicating the unsafe fixture's label.
        clean = Case(CASES[5].name, CASES[5].code.replace('"ssh"', '"restricted"'))
        cases = (CASES[0], clean, CASES[11])
        directory = self.materialize(cases, "formats")
        for mode in ("module-json", "module-sarif", "json", "sarif"):
            with self.subTest(mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, cases)

    def test_malformed_file_marks_partial_preserves_neighbor(self):
        cases = (CASES[0], CASES[-2])
        directory = self.materialize(cases, "partial")
        for mode in ("module-json", "json", "sarif"):
            with self.subTest(mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, cases, partial=True)

    def test_selection_ignore_and_tfvars_exclusion(self):
        unsafe = CASES[0]
        clean = Case(CASES[5].name, CASES[5].code.replace('"ssh"', '"restricted"'))
        directory = self.materialize((unsafe, clean), "selection")
        (directory / "ignored.tf").write_text(unsafe.source, encoding="utf-8")
        (directory / "values.tfvars").write_text(unsafe.source, encoding="utf-8")
        (directory / "example.tf.json").write_text('{"not": "native HCL"}\n', encoding="utf-8")
        self.assert_report(*self.execute(directory, extra=("--exclude=ignored.tf",)), "json", (unsafe, clean))
        selected = self.artifact / "selected-paths.nul"
        selected.write_bytes(os.fsencode(directory / clean.filename) + b"\0")
        self.assert_report(*self.execute(directory, "module-json", ("--files-from=" + str(selected),)),
                           "module-json", (clean,))

    def test_comment_suppression_and_category_skip(self):
        suppressed = Case(CASES[20].name, CASES[20].code.replace('"example"', '"suppressed"'))
        cases = (CASES[0], suppressed, CASES[21])
        directory = self.materialize(cases, "suppression")
        expected = [(case.filename, rule, line, col) for case in cases for rule, line, col in case.expected
                    if rule == RULES["storage"]]
        self.assert_report(*self.execute(directory), "json", cases)
        self.assert_report(*self.execute(directory, extra=("--skip-hcl=1",)), "json", cases, expected_override=expected)

    def test_context_cache_changes_protection(self):
        bucket = Case("main", CASES[11].code.replace(" # expect:storage", ""))
        protector = Case("security", '''
            resource "aws_s3_bucket_public_access_block" "example" {
              bucket = aws_s3_bucket.example.id
              ignore_public_acls = true
            }
        ''')
        directory = self.materialize((bucket, protector), "cache-context")
        for _ in range(2):
            self.assert_report(*self.execute(directory, cached=True), "json", (bucket, protector))
        changed = Case(protector.name, protector.code.replace("true", "false"))
        (directory / changed.filename).write_text(changed.source, encoding="utf-8")
        exposed = Case(bucket.name, CASES[11].code)
        self.assert_report(*self.execute(directory, cached=True), "json", (exposed, changed))

    def test_iam_tls_public_formats_suppression_and_categories(self):
        policies = {case.name: case for case in IAM_CASES}
        providers = {case.name: case for case in TLS_CASES}
        cases = (policies["iam_literal_json_heredoc"], policies["iam_restricted_actions_are_not_administrator"],
                 policies["iam_selected_comment_suppression"], providers["aws_provider_insecure_tls"],
                 providers["aws_provider_selected_comment_suppression"])
        directory = self.materialize(cases, "iam-tls-formats")
        for mode in ("module-json", "module-sarif", "json", "sarif"):
            with self.subTest(mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, cases)
        for category, kept_rule in ((3, RULES["tls"]), (4, RULES["iam"])):
            expected = [(case.filename, rule, line, col) for case in cases for rule, line, col in case.expected
                        if rule == kept_rule]
            self.assert_report(*self.execute(directory, extra=(f"--skip-hcl={category}",)),
                               "json", cases, expected_override=expected)

    def test_iam_unknown_policy_keeps_other_selected_findings(self):
        policies = {case.name: case for case in IAM_CASES}
        providers = {case.name: case for case in TLS_CASES}
        cases = (policies["iam_literal_json_heredoc"], policies["iam_unknown_variable_policy"],
                 providers["aws_provider_insecure_tls"])
        directory = self.materialize(cases, "iam-tls-partial")
        for mode in ("json", "sarif"):
            with self.subTest(mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, cases, partial=True)

    def test_iam_context_cache_invalidates_changed_local_permissions(self):
        policy = Case("main", '''
            resource "aws_iam_policy" "context_policy" {
              policy = jsonencode({
                Statement = [{ Effect = "Allow", Action = local.actions, Resource = "*" }]
              })
            }
        ''')
        permissions = Case("permissions", '''
            locals {
              actions = ["s3:GetObject"]
            }
        ''')
        directory = self.materialize((policy, permissions), "iam-context-cache")
        for _ in range(2):
            self.assert_report(*self.execute(directory, cached=True), "json", (policy, permissions))
        changed = Case(permissions.name, '''
            locals {
              actions = ["*"]
            }
        ''')
        (directory / changed.filename).write_text(changed.source, encoding="utf-8")
        exposed = Case(policy.name, policy.code, locations=(("iam", 2, 3),))
        self.assert_report(*self.execute(directory, cached=True), "json", (exposed, changed))


if __name__ == "__main__":
    unittest.main()
