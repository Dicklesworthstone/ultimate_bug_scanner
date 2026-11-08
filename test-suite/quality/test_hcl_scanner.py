"""Independent, bounded Terraform/AWS oracle for beads mj1j.35/.36.

Labels are source-configuration claims, not deployed AWS reachability claims.
The initial oracle and unsupported-language baseline precede hcl_scan.py.
Authoritative semantics used to choose these cases:
https://github.com/hashicorp/terraform-provider-aws/blob/main/website/docs/r/vpc_security_group_ingress_rule.html.markdown
https://github.com/hashicorp/terraform-provider-aws/blob/main/website/docs/r/security_group_rule.html.markdown
https://github.com/hashicorp/terraform-provider-aws/blob/main/website/docs/r/security_group.html.markdown
https://github.com/hashicorp/terraform-provider-aws/blob/main/website/docs/r/s3_bucket_public_access_block.html.markdown
https://github.com/hashicorp/terraform-provider-aws/blob/main/website/docs/r/s3_bucket_acl.html.markdown
https://github.com/hashicorp/terraform-provider-aws/blob/main/website/docs/d/iam_policy_document.html.markdown
https://github.com/hashicorp/terraform-provider-aws/blob/main/internal/service/iam/policy_document_data_source.go
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
from unittest import mock
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
    Case("iam_policy_document_reference_resolves_selected_definition", '''
        data "aws_iam_policy_document" "example" {
          statement {
            effect = "Allow"
            actions = ["*"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "from_data" {
          policy = data.aws_iam_policy_document.example.json # expect:iam
        }
    '''),
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


# Independently labeled before policy-document resolution is implemented.
# A data source generates JSON; only a selected identity-policy consumer is a
# finding site. Conditions, deny interactions and document merging retain the
# existing incomplete boundary instead of inventing effective AWS permissions.
POLICY_DOCUMENT_CASES = (
    Case("iam_data_default_allow", '''
        data "aws_iam_policy_document" "default_allow" {
          statement {
            actions = ["*"]
            resources = ["*"]
          }
        }
        resource "aws_iam_role_policy" "default_allow" {
          role = "example"
          policy = data.aws_iam_policy_document.default_allow.json # expect:iam
        }
    '''),
    Case("iam_data_minified_json", '''
        data "aws_iam_policy_document" "minified" {
          version = "2012-10-17"
          statement {
            effect = "Allow"
            sid = "Administrator"
            actions = ["*"]
            resources = ["*"]
          }
        }
        resource "aws_iam_user_policy" "minified" {
          user = "example"
          policy = data.aws_iam_policy_document.minified.minified_json # expect:iam
        }
    '''),
    Case("iam_data_old_version_without_variables", '''
        data "aws_iam_policy_document" "old_version" {
          version = "2008-10-17"
          statement {
            actions = ["*"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "old_version" {
          policy = data.aws_iam_policy_document.old_version.json # expect:iam
        }
    '''),
    Case("iam_data_old_version_policy_variables_are_incomplete", '''
        data "aws_iam_policy_document" "old_variables" {
          version = "2008-10-17"
          statement {
            actions = ["*"]
            resources = ["*", "arn:aws:s3:::example/&{aws:username}/*"]
          }
        }
        resource "aws_iam_policy" "old_variables" {
          policy = data.aws_iam_policy_document.old_variables.json
        }
    ''', True),
    Case("iam_data_current_version_policy_variables_keep_wildcard", '''
        data "aws_iam_policy_document" "current_variables" {
          version = "2012-10-17"
          statement {
            actions = ["*"]
            resources = ["*", "arn:aws:s3:::example/&{aws:username}/*"]
          }
        }
        resource "aws_iam_policy" "current_variables" {
          policy = data.aws_iam_policy_document.current_variables.json # expect:iam
        }
    '''),
    Case("iam_data_local_output_chain_and_statement_values", '''
        locals {
          statement = { actions = ["*"], resources = ["*"] }
          selected_json = data.aws_iam_policy_document.local_values.json
          policy_json = (local.selected_json)
        }
        data "aws_iam_policy_document" "local_values" {
          statement {
            effect = "Allow"
            actions = local.statement.actions
            resources = local.statement.resources
          }
        }
        resource "aws_iam_group_policy" "local_values" {
          group = "example"
          policy = local.policy_json # expect:iam
        }
    '''),
    Case("iam_data_repeated_default_sid", '''
        data "aws_iam_policy_document" "default_sids" {
          statement {
            actions = ["s3:GetObject"]
            resources = ["arn:aws:s3:::example/*"]
          }
          statement {
            actions = ["*"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "default_sids" {
          policy = data.aws_iam_policy_document.default_sids.json # expect:iam
        }
    '''),
    Case("iam_data_repeated_explicit_empty_sid", '''
        data "aws_iam_policy_document" "empty_sids" {
          statement {
            sid = ""
            actions = ["s3:GetObject"]
            resources = ["*"]
          }
          statement {
            sid = ""
            actions = ["*"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "empty_sids" {
          policy = data.aws_iam_policy_document.empty_sids.json # expect:iam
        }
    '''),
    Case("iam_data_selected_provider_alias", '''
        terraform {
          required_providers {
            cloud = { source = "hashicorp/aws" }
          }
        }
        provider "cloud" {
          alias = "selected"
        }
        data "aws_iam_policy_document" "selected_alias" {
          provider = cloud.selected
          statement {
            actions = ["*"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "selected_alias" {
          policy = data.aws_iam_policy_document.selected_alias.json # expect:iam
        }
    '''),
    Case("iam_data_restricted_actions", '''
        data "aws_iam_policy_document" "limited_actions" {
          statement {
            actions = ["s3:GetObject", "s3:ListBucket"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "limited_actions" {
          policy = data.aws_iam_policy_document.limited_actions.json
        }
    '''),
    Case("iam_data_restricted_resources", '''
        data "aws_iam_policy_document" "limited_resources" {
          statement {
            actions = ["*"]
            resources = ["arn:aws:s3:::selected/*"]
          }
        }
        resource "aws_iam_policy" "limited_resources" {
          policy = data.aws_iam_policy_document.limited_resources.json
        }
    '''),
    Case("iam_data_deny_only", '''
        data "aws_iam_policy_document" "only_deny" {
          statement {
            effect = "Deny"
            actions = ["*"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "only_deny" {
          policy = data.aws_iam_policy_document.only_deny.json
        }
    '''),
    Case("iam_data_unused_grant_does_not_create_finding", '''
        data "aws_iam_policy_document" "unused" {
          statement {
            actions = ["*"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "independent" {
          policy = jsonencode({
            Statement = [{ Effect = "Allow", Action = "s3:GetObject", Resource = "*" }]
          })
        }
    '''),
    Case("iam_data_inactive_consumer_is_not_evaluated", '''
        data "aws_iam_policy_document" "inactive_consumer" {
          statement {
            actions = var.actions
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "inactive_consumer" {
          count = 0
          policy = data.aws_iam_policy_document.inactive_consumer.json
        }
    '''),
    Case("iam_data_comment_and_literal_decoys", '''
        # data "aws_iam_policy_document" "decoy" { statement { actions = ["*"] } }
        locals {
          message = "data.aws_iam_policy_document.decoy.json"
        }
        resource "aws_iam_policy" "literal_control" {
          policy = jsonencode({
            Statement = [{ Effect = "Allow", Action = "s3:GetObject", Resource = "*" }]
          })
        }
    '''),
    Case("iam_data_selected_consumer_suppression", '''
        data "aws_iam_policy_document" "suppressed_data" {
          statement {
            actions = ["*"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "suppressed_data" {
          policy = data.aws_iam_policy_document.suppressed_data.json # ubs:ignore[hcl.aws.iam-wildcard-privilege]
        }
    '''),
    Case("iam_data_conditional_wildcard_is_incomplete", '''
        data "aws_iam_policy_document" "conditional" {
          statement {
            actions = ["*"]
            resources = ["*"]
            condition {
              test = "Bool"
              variable = "aws:MultiFactorAuthPresent"
              values = ["true"]
            }
          }
        }
        resource "aws_iam_policy" "conditional" {
          policy = data.aws_iam_policy_document.conditional.json
        }
    ''', True),
    Case("iam_data_allow_and_deny_is_incomplete", '''
        data "aws_iam_policy_document" "deny_constraint" {
          statement {
            actions = ["*"]
            resources = ["*"]
          }
          statement {
            effect = "Deny"
            actions = ["iam:*"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "deny_constraint" {
          policy = data.aws_iam_policy_document.deny_constraint.json
        }
    ''', True),
    Case("iam_data_dynamic_statement_is_incomplete", '''
        data "aws_iam_policy_document" "dynamic_statement" {
          dynamic "statement" {
            for_each = var.statements
            content {
              actions = ["*"]
              resources = ["*"]
            }
          }
        }
        resource "aws_iam_policy" "dynamic_statement" {
          policy = data.aws_iam_policy_document.dynamic_statement.json
        }
    ''', True),
    Case("iam_data_unknown_action_is_incomplete", '''
        data "aws_iam_policy_document" "unknown_action" {
          statement {
            actions = var.actions
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "unknown_action" {
          policy = data.aws_iam_policy_document.unknown_action.json
        }
    ''', True),
    Case("iam_data_unknown_effect_is_incomplete", '''
        data "aws_iam_policy_document" "unknown_effect" {
          statement {
            effect = var.effect
            actions = ["*"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "unknown_effect" {
          policy = data.aws_iam_policy_document.unknown_effect.json
        }
    ''', True),
    Case("iam_data_principals_are_outside_identity_model", '''
        data "aws_iam_policy_document" "principal" {
          statement {
            actions = ["*"]
            resources = ["*"]
            principals {
              type = "AWS"
              identifiers = ["*"]
            }
          }
        }
        resource "aws_iam_policy" "principal" {
          policy = data.aws_iam_policy_document.principal.json
        }
    ''', True),
    Case("iam_data_not_actions_are_outside_selected_model", '''
        data "aws_iam_policy_document" "complement_actions" {
          statement {
            not_actions = ["iam:*"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "complement_actions" {
          policy = data.aws_iam_policy_document.complement_actions.json
        }
    ''', True),
    Case("iam_data_not_resources_are_outside_selected_model", '''
        data "aws_iam_policy_document" "complement_resources" {
          statement {
            actions = ["*"]
            not_resources = ["arn:aws:s3:::protected/*"]
          }
        }
        resource "aws_iam_policy" "complement_resources" {
          policy = data.aws_iam_policy_document.complement_resources.json
        }
    ''', True),
    Case("iam_data_provider_rebinding_is_incomplete", '''
        terraform {
          required_providers {
            aws = { source = "example/not-aws" }
            actual = { source = "hashicorp/aws" }
          }
        }
        data "aws_iam_policy_document" "foreign_default" {
          statement {
            actions = ["*"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "foreign_default" {
          provider = actual
          policy = data.aws_iam_policy_document.foreign_default.json
        }
    ''', True),
    Case("iam_data_unknown_provider_is_incomplete", '''
        data "aws_iam_policy_document" "unknown_provider" {
          provider = var.provider
          statement {
            actions = ["*"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "unknown_provider" {
          policy = data.aws_iam_policy_document.unknown_provider.json
        }
    ''', True),
    Case("iam_data_duplicate_address_is_incomplete", '''
        data "aws_iam_policy_document" "duplicate" {
          statement {
            actions = ["*"]
            resources = ["*"]
          }
        }
        data "aws_iam_policy_document" "duplicate" {
          statement {
            actions = ["s3:GetObject"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "duplicate" {
          policy = data.aws_iam_policy_document.duplicate.json
        }
    ''', True),
    Case("iam_data_missing_definition_is_incomplete", '''
        resource "aws_iam_policy" "missing" {
          policy = data.aws_iam_policy_document.missing.json
        }
    ''', True),
    Case("iam_data_duplicate_named_sid_is_incomplete", '''
        data "aws_iam_policy_document" "duplicate_sid" {
          statement {
            sid = "Same"
            actions = ["s3:GetObject"]
            resources = ["*"]
          }
          statement {
            sid = "Same"
            actions = ["*"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "duplicate_sid" {
          policy = data.aws_iam_policy_document.duplicate_sid.json
        }
    ''', True),
    Case("iam_data_unindexed_count_is_incomplete", '''
        data "aws_iam_policy_document" "counted" {
          count = 1
          statement {
            actions = ["*"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "counted" {
          policy = data.aws_iam_policy_document.counted.json
        }
    ''', True),
    Case("iam_data_indexed_count_is_outside_selected_model", '''
        data "aws_iam_policy_document" "indexed" {
          count = 1
          statement {
            actions = ["*"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "indexed" {
          policy = data.aws_iam_policy_document.indexed[0].json
        }
    ''', True),
    Case("iam_data_for_each_is_outside_selected_model", '''
        data "aws_iam_policy_document" "instances" {
          for_each = { selected = "example" }
          statement {
            actions = ["*"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "instances" {
          policy = data.aws_iam_policy_document.instances.json
        }
    ''', True),
    Case("iam_data_source_document_merge_is_incomplete", '''
        data "aws_iam_policy_document" "source_merge" {
          source_policy_documents = [jsonencode({
            Statement = [{ Sid = "Selected", Effect = "Allow", Action = "*", Resource = "*" }]
          })]
          statement {
            sid = "Selected"
            actions = ["s3:GetObject"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "source_merge" {
          policy = data.aws_iam_policy_document.source_merge.json
        }
    ''', True),
    Case("iam_data_override_document_merge_is_incomplete", '''
        data "aws_iam_policy_document" "override_merge" {
          override_policy_documents = [jsonencode({
            Statement = [{ Sid = "Selected", Effect = "Allow", Action = "s3:GetObject", Resource = "*" }]
          })]
          statement {
            sid = "Selected"
            actions = ["*"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "override_merge" {
          policy = data.aws_iam_policy_document.override_merge.json
        }
    ''', True),
    Case("iam_data_legacy_source_json_is_incomplete", '''
        data "aws_iam_policy_document" "legacy_source" {
          source_json = "{}"
          statement {
            actions = ["*"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "legacy_source" {
          policy = data.aws_iam_policy_document.legacy_source.json
        }
    ''', True),
    Case("iam_data_local_reference_cycle_is_incomplete", '''
        locals {
          document = data.aws_iam_policy_document.cycle.json
        }
        data "aws_iam_policy_document" "cycle" {
          statement {
            actions = local.document
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "cycle" {
          policy = local.document
        }
    ''', True),
    Case("iam_data_provider_requirement_cycle_is_incomplete", '''
        terraform {
          required_providers {
            aws = { source = local.provider_source }
          }
        }
        locals {
          provider_source = local.document
          document = data.aws_iam_policy_document.provider_cycle.json
        }
        data "aws_iam_policy_document" "provider_cycle" {
          statement {
            actions = local.document
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "provider_cycle" {
          policy = local.document
        }
    ''', True),
    Case("iam_data_object_member_cycle_keeps_independent_finding", '''
        locals {
          bundle = {
            actions = ["*"]
            generated = data.aws_iam_policy_document.hidden_cycle.json
          }
        }
        data "aws_iam_policy_document" "hidden_cycle" {
          statement {
            actions = local.bundle.actions
            resources = ["*"]
          }
        }
        data "aws_iam_policy_document" "independent_cycle_control" {
          statement {
            actions = ["*"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "hidden_cycle" {
          policy = data.aws_iam_policy_document.hidden_cycle.json
        }
        resource "aws_iam_policy" "independent_cycle_control" {
          policy = data.aws_iam_policy_document.independent_cycle_control.json # expect:iam
        }
    ''', True),
    Case("iam_data_cached_cycle_in_unused_object_member_is_incomplete", '''
        locals {
          recursive = { again = local.recursive }
          bundle = { actions = ["*"], unused = local.recursive }
        }
        resource "aws_iam_policy" "first_cycle_use" {
          policy = local.recursive
        }
        data "aws_iam_policy_document" "cached_cycle" {
          statement {
            actions = local.bundle.actions
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "second_cycle_use" {
          policy = data.aws_iam_policy_document.cached_cycle.json
        }
    ''', True),
    Case("iam_data_unknown_unselected_object_member_is_independent", '''
        locals {
          bundle = { actions = ["*"], unused = var.description }
        }
        data "aws_iam_policy_document" "selected_member" {
          statement {
            actions = local.bundle.actions
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "selected_member" {
          policy = data.aws_iam_policy_document.selected_member.json # expect:iam
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

    def test_iam_data_selected_sibling_files_and_module_isolation(self):
        analyzer = importlib.import_module("ubs_core.hcl_scan")
        consumer = Case("main", '''
            resource "aws_iam_policy" "selected_sibling" {
              policy = local.policy_json # expect:iam
            }
        ''')
        aliases = Case("aliases", '''
            locals {
              policy_json = data.aws_iam_policy_document.selected_sibling.json
            }
        ''')
        document = Case("permissions", '''
            data "aws_iam_policy_document" "selected_sibling" {
              statement {
                actions = ["*"]
                resources = ["*"]
              }
            }
        ''')
        directory = self.materialize((consumer, aliases, document), "iam-data-module-context")
        consumer_path, aliases_path, document_path = (str(directory / case.filename)
                                                    for case in (consumer, aliases, document))
        other = directory / "other-module"
        other.mkdir()
        (other / document.filename).write_text(document.source, encoding="utf-8")
        scenarios = (
            ("selected-siblings", {consumer_path: consumer.source, aliases_path: aliases.source,
                                   document_path: document.source}, False),
            ("definition-not-selected", {consumer_path: consumer.source, aliases_path: aliases.source}, True),
            ("different-module", {consumer_path: consumer.source, aliases_path: aliases.source,
                                  str(other / document.filename): document.source}, True),
        )
        for name, sources, partial in scenarios:
            with self.subTest(selection=name):
                records, errors = analyzer.analyze_sources(sources)
                actual = sorted((row["path"], row["rule"], row["line"], row["col"]) for row in records)
                expected = [] if partial else [(consumer_path, rule, line, col)
                                               for rule, line, col in consumer.expected]
                (directory / (name + ".json")).write_text(json.dumps({
                    **self.identity, "selected_sources": list(sources), "expected": expected,
                    "actual": actual, "findings": records, "errors": errors, "incomplete": partial,
                    "analyzer_sha256": hashlib.sha256(Path(analyzer.__file__).read_bytes()).hexdigest(),
                }, indent=2) + "\n", encoding="utf-8")
                self.assertEqual(bool(errors), partial, (sources, records, errors))
                self.assertEqual(actual, expected, (sources, records, errors))

    def test_iam_data_encoded_document_budget_is_incomplete(self):
        analyzer = importlib.import_module("ubs_core.hcl_scan")
        # The source strings fit the cap, but JSON escaping expands the key
        # well past it. This tests serialized bytes, not just source length.
        resource = "arn:aws:s3:::example/" + "\u00e9" * 80
        case = Case("iam_data_encoded_budget", '''
            data "aws_iam_policy_document" "encoded_budget" {
              statement {
                actions = ["*"]
                resources = ["*", %s]
              }
            }
            resource "aws_iam_policy" "encoded_budget" {
              policy = data.aws_iam_policy_document.encoded_budget.json # expect:iam
            }
        ''' % json.dumps(resource, ensure_ascii=False))
        self.check_native(case)
        limited = Case(case.name + "_limited", case.code.replace(" # expect:iam", ""), True)
        with mock.patch.object(analyzer, "MAX_POLICY_BYTES", 256):
            self.check_native(limited)

    def test_iam_data_total_generated_document_budget_is_incomplete(self):
        analyzer = importlib.import_module("ubs_core.hcl_scan")
        # Each document fits comfortably, while many references to the same
        # literal produce more retained JSON than the entire source context.
        # Keep the cap above the input size so this reaches the output budget.
        identifier = "A" * 256
        declarations = [f'locals {{ identifier = "{identifier}" }}']
        for index in range(12):
            declarations.append('''
data "aws_iam_policy_document" "document%d" {
  statement {
    sid = local.identifier
    actions = ["*"]
    resources = ["*"]
  }
}
resource "aws_iam_policy" "document%d" {
  policy = data.aws_iam_policy_document.document%d.json
}
''' % (index, index, index))
        case = Case("iam_data_aggregate_budget", "\n".join(declarations))
        directory = self.materialize((case,), case.name)
        source = directory / case.filename
        limit = len(case.source.encode("utf-8")) + 64
        with mock.patch.object(analyzer, "MAX_CONTEXT_BYTES", limit), \
                mock.patch.object(analyzer, "MAX_POLICY_BYTES", 1024):
            records, errors = analyzer.analyze_source(case.source, str(source))
        (directory / "receipt.json").write_text(json.dumps({
            **self.identity, "findings": records, "errors": errors, "context_limit": limit,
            "per_document_limit": 1024, "source_bytes": len(case.source.encode("utf-8")),
            "analyzer_sha256": hashlib.sha256(Path(analyzer.__file__).read_bytes()).hexdigest(),
        }, indent=2) + "\n", encoding="utf-8")
        self.assertTrue(errors, (records, errors))
        self.assertTrue(records, "retain independently proved earlier documents when a later document exhausts the budget")
        self.assertLess(len(records), 12, (records, errors))
        for record in records:
            self.assertEqual(record["rule"], RULES["iam"], record)
            self.assertEqual(record["path"], str(source), record)

    def test_iam_data_shared_variable_substitutions_are_bounded_before_encoding(self):
        analyzer = importlib.import_module("ubs_core.hcl_scan")
        resource = "arn:aws:s3:::" + "a" * 96 + "/&{aws:username}/*"
        case = Case("iam_data_shared_resource_budget", '''
            locals {
              resource = %s
            }
            data "aws_iam_policy_document" "shared_resources" {
              statement {
                actions = ["*"]
                resources = ["*", local.resource, local.resource, local.resource, local.resource]
              }
            }
            resource "aws_iam_policy" "shared_resources" {
              policy = data.aws_iam_policy_document.shared_resources.json
            }
        ''' % json.dumps(resource), True)
        directory = self.materialize((case,), case.name)
        source = directory / case.filename
        # The limit is deliberately tiny. A serializer-only limit is too late:
        # transforming every repeated string has already allocated the larger
        # result before the serializer can reject it.
        with mock.patch.object(analyzer, "MAX_POLICY_BYTES", 256), \
                mock.patch.object(analyzer.json.JSONEncoder, "iterencode",
                                  side_effect=AssertionError("oversized transformed document reached the serializer")):
            records, errors = analyzer.analyze_source(case.source, str(source))
        (directory / "receipt.json").write_text(json.dumps({
            **self.identity, "findings": records, "errors": errors, "per_document_limit": 256,
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "analyzer_sha256": hashlib.sha256(Path(analyzer.__file__).read_bytes()).hexdigest(),
        }, indent=2) + "\n", encoding="utf-8")
        self.assertEqual(records, [], (records, errors))
        self.assertTrue(errors, "expanded resources must become incomplete before reaching the serializer")


def native_test(case):
    def run(self):
        self.check_native(case)
    return run


for _case in CASES + REVIEW_CASES + IAM_CASES + TLS_CASES + POLICY_DOCUMENT_CASES:
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

    def test_iam_data_public_formats_suppression_and_categories(self):
        cases_by_name = {case.name: case for case in POLICY_DOCUMENT_CASES}
        cases = tuple(cases_by_name[name] for name in (
            "iam_data_default_allow", "iam_data_minified_json", "iam_data_restricted_actions",
            "iam_data_selected_consumer_suppression"))
        directory = self.materialize(cases, "iam-data-formats")
        for mode in ("module-json", "module-sarif", "json", "sarif"):
            with self.subTest(mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, cases)
        self.assert_report(*self.execute(directory, extra=("--skip-hcl=3",)),
                           "json", cases, expected_override=[])

    def test_iam_data_partial_keeps_independent_proven_finding(self):
        cases_by_name = {case.name: case for case in POLICY_DOCUMENT_CASES}
        cases = tuple(cases_by_name[name] for name in (
            "iam_data_default_allow", "iam_data_conditional_wildcard_is_incomplete",
            "iam_data_unknown_action_is_incomplete"))
        directory = self.materialize(cases, "iam-data-partial")
        for mode in ("module-json", "module-sarif", "json", "sarif"):
            with self.subTest(mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, cases, partial=True)

    def test_iam_data_cache_invalidates_changed_selected_definition(self):
        consumer = Case("main", '''
            resource "aws_iam_policy" "cached_document" {
              policy = data.aws_iam_policy_document.cached_document.json
            }
        ''')
        document = Case("permissions", '''
            data "aws_iam_policy_document" "cached_document" {
              statement {
                actions = ["s3:GetObject"]
                resources = ["*"]
              }
            }
        ''')
        directory = self.materialize((consumer, document), "iam-data-cache")
        for attempt in range(2):
            with self.subTest(cache_state="restricted-" + str(attempt)):
                self.assert_report(*self.execute(directory, cached=True), "json", (consumer, document))
        changed = Case(document.name, '''
            data "aws_iam_policy_document" "cached_document" {
              statement {
                actions = ["*"]
                resources = ["*"]
              }
            }
        ''')
        (directory / changed.filename).write_text(changed.source, encoding="utf-8")
        exposed = Case(consumer.name, consumer.code, locations=(("iam", 2, 3),))
        with self.subTest(cache_state="broadened-definition"):
            self.assert_report(*self.execute(directory, cached=True), "json", (exposed, changed))
        with self.subTest(selection="definition-excluded"):
            self.assert_report(*self.execute(directory, extra=("--exclude=permissions.tf",), cached=True),
                               "json", (consumer,), partial=True)
        with self.subTest(selection="definition-restored"):
            self.assert_report(*self.execute(directory, cached=True), "json", (exposed, changed))


if __name__ == "__main__":
    unittest.main()
