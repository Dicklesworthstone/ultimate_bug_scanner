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
https://github.com/hashicorp/hcl/blob/main/json/spec.md
https://github.com/hashicorp/hcl/blob/main/json/public.go
https://developer.hashicorp.com/terraform/language/syntax/json
https://developer.hashicorp.com/terraform/language/attr-as-blocks
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


class JSONCase(Case):
    @property
    def filename(self):
        return self.name + ".tf.json"


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
# finding site. Conditions and deny interactions retain the incomplete boundary
# instead of inventing effective AWS permissions. Composition cases below are
# independently labeled against the provider's ordered statement replacement.
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
    Case("iam_data_own_named_statement_restricts_source_grant", '''
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
    '''),
    Case("iam_data_override_named_statement_restricts_own_grant", '''
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
    '''),
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


# Pre-implementation composition oracle: source SID uniqueness is checked
# before replacement; own statements replace sources; overrides replace in
# order. Anonymous statements append, and replacing a statement replaces its
# complete Effect/Action/Resource/Condition rather than merging those fields.
POLICY_COMPOSITION_CASES = (
    Case("iam_composed_source_only_grant", '''
        data "aws_iam_policy_document" "source_only" {
          source_policy_documents = [jsonencode({
            Statement = [{ Sid = "Administrator", Effect = "Allow", Action = "*", Resource = "*" }]
          })]
        }
        resource "aws_iam_policy" "source_only" {
          policy = data.aws_iam_policy_document.source_only.json # expect:iam
        }
    '''),
    Case("iam_composed_last_override_broadens", '''
        data "aws_iam_policy_document" "last_broadens" {
          statement {
            sid = "Selected"
            actions = ["s3:GetObject"]
            resources = ["*"]
          }
          override_policy_documents = [
            jsonencode({ Statement = [{ Sid = "Selected", Effect = "Allow", Action = "s3:ListBucket", Resource = "*" }] }),
            jsonencode({ Statement = [{ Sid = "Selected", Effect = "Allow", Action = "*", Resource = "*" }] })
          ]
        }
        resource "aws_iam_policy" "last_broadens" {
          policy = data.aws_iam_policy_document.last_broadens.minified_json # expect:iam
        }
    '''),
    Case("iam_composed_last_override_restricts", '''
        data "aws_iam_policy_document" "last_restricts" {
          statement {
            sid = "Selected"
            actions = ["*"]
            resources = ["*"]
          }
          override_policy_documents = [
            jsonencode({ Statement = [{ Sid = "Selected", Effect = "Allow", Action = "*", Resource = "*" }] }),
            jsonencode({ Statement = [{ Sid = "Selected", Effect = "Allow", Action = "s3:GetObject", Resource = "*" }] })
          ]
        }
        resource "aws_iam_policy" "last_restricts" {
          policy = data.aws_iam_policy_document.last_restricts.json
        }
    '''),
    Case("iam_composed_repeated_override_sid_last_broadens", '''
        data "aws_iam_policy_document" "same_document_broadens" {
          override_policy_documents = [jsonencode({ Statement = [
            { Sid = "Selected", Effect = "Allow", Action = "s3:GetObject", Resource = "*" },
            { Sid = "Selected", Effect = "Allow", Action = "*", Resource = "*" }
          ] })]
        }
        resource "aws_iam_policy" "same_document_broadens" {
          policy = data.aws_iam_policy_document.same_document_broadens.json # expect:iam
        }
    '''),
    Case("iam_composed_repeated_override_sid_last_restricts", '''
        data "aws_iam_policy_document" "same_document_restricts" {
          override_policy_documents = [jsonencode({ Statement = [
            { Sid = "Selected", Effect = "Allow", Action = "*", Resource = "*" },
            { Sid = "Selected", Effect = "Allow", Action = "s3:GetObject", Resource = "*" }
          ] })]
        }
        resource "aws_iam_policy" "same_document_restricts" {
          policy = data.aws_iam_policy_document.same_document_restricts.json
        }
    '''),
    Case("iam_composed_absent_sid_is_not_overridden", '''
        data "aws_iam_policy_document" "anonymous_source" {
          source_policy_documents = [jsonencode({
            Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
          })]
          override_policy_documents = [jsonencode({
            Statement = [{ Effect = "Allow", Action = "s3:GetObject", Resource = "*" }]
          })]
        }
        resource "aws_iam_policy" "anonymous_source" {
          policy = data.aws_iam_policy_document.anonymous_source.json # expect:iam
        }
    '''),
    Case("iam_composed_empty_sid_is_not_overridden", '''
        data "aws_iam_policy_document" "empty_source_sid" {
          source_policy_documents = [jsonencode({
            Statement = [{ Sid = "", Effect = "Allow", Action = "*", Resource = "*" }]
          })]
          statement {
            sid = ""
            actions = ["s3:GetObject"]
            resources = ["*"]
          }
          override_policy_documents = [jsonencode({
            Statement = [{ Sid = "", Effect = "Allow", Action = "s3:ListBucket", Resource = "*" }]
          })]
        }
        resource "aws_iam_policy" "empty_source_sid" {
          policy = data.aws_iam_policy_document.empty_source_sid.json # expect:iam
        }
    '''),
    Case("iam_composed_duplicate_source_sids_are_incomplete", '''
        data "aws_iam_policy_document" "duplicate_sources" {
          source_policy_documents = [
            jsonencode({ Statement = [{ Sid = "Same", Effect = "Allow", Action = "*", Resource = "*" }] }),
            jsonencode({ Statement = [{ Sid = "Same", Effect = "Allow", Action = "s3:GetObject", Resource = "*" }] })
          ]
          statement {
            sid = "Same"
            actions = ["s3:GetObject"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "duplicate_sources" {
          policy = data.aws_iam_policy_document.duplicate_sources.json
        }
    ''', True),
    Case("iam_composed_duplicate_sids_within_source_are_incomplete", '''
        data "aws_iam_policy_document" "duplicates_inside_source" {
          source_policy_documents = [jsonencode({ Statement = [
            { Sid = "Same", Effect = "Allow", Action = "*", Resource = "*" },
            { Sid = "Same", Effect = "Allow", Action = "s3:GetObject", Resource = "*" }
          ] })]
          override_policy_documents = [jsonencode({
            Statement = [{ Sid = "Same", Effect = "Allow", Action = "s3:ListBucket", Resource = "*" }]
          })]
        }
        resource "aws_iam_policy" "duplicates_inside_source" {
          policy = data.aws_iam_policy_document.duplicates_inside_source.json
        }
    ''', True),
    Case("iam_composed_duplicate_own_sids_cannot_be_repaired_by_override", '''
        data "aws_iam_policy_document" "duplicate_own" {
          statement {
            sid = "Same"
            actions = ["*"]
            resources = ["*"]
          }
          statement {
            sid = "Same"
            actions = ["s3:GetObject"]
            resources = ["*"]
          }
          override_policy_documents = [jsonencode({
            Statement = [{ Sid = "Same", Effect = "Allow", Action = "s3:ListBucket", Resource = "*" }]
          })]
        }
        resource "aws_iam_policy" "duplicate_own" {
          policy = data.aws_iam_policy_document.duplicate_own.json
        }
    ''', True),
    Case("iam_composed_locals_and_selected_data_chain", '''
        locals {
          selected = data.aws_iam_policy_document.chain_source.minified_json
          documents = [local.selected]
          final_json = data.aws_iam_policy_document.chain_target.json
        }
        data "aws_iam_policy_document" "chain_source" {
          statement {
            actions = ["*"]
            resources = ["*"]
          }
        }
        data "aws_iam_policy_document" "chain_target" {
          source_policy_documents = local.documents
        }
        resource "aws_iam_policy" "chain_target" {
          policy = local.final_json # expect:iam
        }
    '''),
    Case("iam_composed_inherited_deny_remains_incomplete", '''
        data "aws_iam_policy_document" "inherited_deny" {
          source_policy_documents = [jsonencode({ Statement = [
            { Sid = "Grant", Effect = "Allow", Action = "*", Resource = "*" },
            { Sid = "Restriction", Effect = "Deny", Action = "iam:*", Resource = "*" }
          ] })]
        }
        resource "aws_iam_policy" "inherited_deny" {
          policy = data.aws_iam_policy_document.inherited_deny.json
        }
    ''', True),
    Case("iam_composed_replaced_deny_no_longer_constrains_grant", '''
        data "aws_iam_policy_document" "replaced_deny" {
          source_policy_documents = [jsonencode({ Statement = [
            { Sid = "Grant", Effect = "Allow", Action = "*", Resource = "*" },
            { Sid = "Restriction", Effect = "Deny", Action = "iam:*", Resource = "*" }
          ] })]
          statement {
            sid = "Restriction"
            actions = ["s3:GetObject"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "replaced_deny" {
          policy = data.aws_iam_policy_document.replaced_deny.json # expect:iam
        }
    '''),
    Case("iam_composed_inherited_condition_remains_incomplete", '''
        data "aws_iam_policy_document" "inherited_condition" {
          source_policy_documents = [jsonencode({ Statement = [{
            Sid = "Conditional"
            Effect = "Allow"
            Action = "*"
            Resource = "*"
            Condition = { Bool = { "aws:MultiFactorAuthPresent" = "true" } }
          }] })]
        }
        resource "aws_iam_policy" "inherited_condition" {
          policy = data.aws_iam_policy_document.inherited_condition.json
        }
    ''', True),
    Case("iam_composed_replaced_condition_no_longer_constrains_grant", '''
        data "aws_iam_policy_document" "replaced_condition" {
          source_policy_documents = [jsonencode({ Statement = [{
            Sid = "Conditional"
            Effect = "Allow"
            Action = "*"
            Resource = "*"
            Condition = { Bool = { "aws:MultiFactorAuthPresent" = "true" } }
          }] })]
          override_policy_documents = [jsonencode({
            Statement = [{ Sid = "Conditional", Effect = "Allow", Action = "*", Resource = "*" }]
          })]
        }
        resource "aws_iam_policy" "replaced_condition" {
          policy = data.aws_iam_policy_document.replaced_condition.json # expect:iam
        }
    '''),
    Case("iam_composed_unknown_sources_are_incomplete", '''
        data "aws_iam_policy_document" "unknown_sources" {
          source_policy_documents = var.documents
          statement {
            actions = ["*"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "unknown_sources" {
          policy = data.aws_iam_policy_document.unknown_sources.json
        }
        resource "aws_iam_policy" "known_independent_source_control" {
          policy = jsonencode({ # expect:iam
            Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
          })
        }
    ''', True),
    Case("iam_composed_unknown_override_is_incomplete", '''
        data "aws_iam_policy_document" "unknown_override" {
          statement {
            sid = "Selected"
            actions = ["*"]
            resources = ["*"]
          }
          override_policy_documents = [var.override_json]
        }
        resource "aws_iam_policy" "unknown_override" {
          policy = data.aws_iam_policy_document.unknown_override.json
        }
    ''', True),
    Case("iam_composed_cycle_is_incomplete", '''
        data "aws_iam_policy_document" "cycle_left" {
          source_policy_documents = [data.aws_iam_policy_document.cycle_right.json]
        }
        data "aws_iam_policy_document" "cycle_right" {
          override_policy_documents = [data.aws_iam_policy_document.cycle_left.json]
        }
        resource "aws_iam_policy" "cycle_left" {
          policy = data.aws_iam_policy_document.cycle_left.json
        }
    ''', True),
    Case("iam_composed_invalid_json_is_incomplete", '''
        data "aws_iam_policy_document" "invalid_source_json" {
          source_policy_documents = ["{broken json}"]
          statement {
            actions = ["*"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "invalid_source_json" {
          policy = data.aws_iam_policy_document.invalid_source_json.json
        }
    ''', True),
    Case("iam_composed_complement_source_is_incomplete", '''
        data "aws_iam_policy_document" "complement_source" {
          source_policy_documents = [jsonencode({
            Statement = [{ Effect = "Allow", NotAction = "iam:*", Resource = "*" }]
          })]
        }
        resource "aws_iam_policy" "complement_source" {
          policy = data.aws_iam_policy_document.complement_source.json
        }
    ''', True),
    Case("iam_composed_principal_source_is_incomplete", '''
        data "aws_iam_policy_document" "principal_source" {
          source_policy_documents = [jsonencode({
            Statement = [{ Effect = "Allow", Action = "*", Resource = "*", Principal = "*" }]
          })]
        }
        resource "aws_iam_policy" "principal_source" {
          policy = data.aws_iam_policy_document.principal_source.json
        }
    ''', True),
    Case("iam_composed_source_statement_object_is_invalid", '''
        data "aws_iam_policy_document" "statement_object" {
          source_policy_documents = [jsonencode({
            Statement = { Effect = "Allow", Action = "*", Resource = "*" }
          })]
        }
        resource "aws_iam_policy" "statement_object" {
          policy = data.aws_iam_policy_document.statement_object.json
        }
    ''', True),
    Case("iam_composed_duplicate_source_json_keys_are_invalid", '''
        data "aws_iam_policy_document" "duplicate_json_key" {
          source_policy_documents = [<<POLICY
        {"Statement":[{"Effect":"Deny","Effect":"Allow","Action":"*","Resource":"*"}]}
        POLICY
          ]
        }
        resource "aws_iam_policy" "duplicate_json_key" {
          policy = data.aws_iam_policy_document.duplicate_json_key.json
        }
    ''', True),
    Case("iam_composed_empty_lists_preserve_own_grant", '''
        data "aws_iam_policy_document" "empty_lists" {
          source_policy_documents = []
          override_policy_documents = []
          statement {
            actions = ["*"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "empty_lists" {
          policy = data.aws_iam_policy_document.empty_lists.json # expect:iam
        }
    '''),
    Case("iam_composed_empty_documents_are_noops", '''
        data "aws_iam_policy_document" "empty_documents" {
          source_policy_documents = ["{}", jsonencode({ Version = "2012-10-17" }),
                                     jsonencode({ Statement = [] }), jsonencode({ Statement = null })]
          override_policy_documents = ["{}", jsonencode({ Statement = [] })]
          statement {
            actions = ["*"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "empty_documents" {
          policy = data.aws_iam_policy_document.empty_documents.json # expect:iam
        }
    '''),
    Case("iam_composed_optional_null_lists_are_omitted", '''
        data "aws_iam_policy_document" "null_collections" {
          source_policy_documents = null
          override_policy_documents = null
          statement {
            actions = ["*"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "null_collections" {
          policy = data.aws_iam_policy_document.null_collections.json # expect:iam
        }
    '''),
    Case("iam_composed_null_list_members_are_skipped", '''
        data "aws_iam_policy_document" "null_members" {
          source_policy_documents = [null, jsonencode({
            Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
          }), null]
          override_policy_documents = [null]
        }
        resource "aws_iam_policy" "null_members" {
          policy = data.aws_iam_policy_document.null_members.json # expect:iam
        }
    '''),
    Case("iam_composed_source_version_cannot_enable_old_own_variables", '''
        data "aws_iam_policy_document" "old_own_variables" {
          version = "2008-10-17"
          source_policy_documents = [jsonencode({ Version = "2012-10-17", Statement = [] })]
          statement {
            actions = ["*"]
            resources = ["*", "arn:aws:s3:::example/&{aws:username}/*"]
          }
        }
        resource "aws_iam_policy" "old_own_variables" {
          policy = data.aws_iam_policy_document.old_own_variables.json
        }
    ''', True),
    Case("iam_composed_cached_cycle_cannot_hide_in_object_projection", '''
        locals {
          inherited = data.aws_iam_policy_document.inherited_cycle.json
          selected = { actions = ["*"], unused = local.inherited }
        }
        data "aws_iam_policy_document" "inherited_cycle" {
          source_policy_documents = [local.inherited]
        }
        resource "aws_iam_policy" "first_cycle_use" {
          policy = local.inherited
        }
        data "aws_iam_policy_document" "projected_cycle" {
          statement {
            actions = local.selected.actions
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "projected_cycle" {
          policy = data.aws_iam_policy_document.projected_cycle.json
        }
        resource "aws_iam_policy" "independent_cycle_control" {
          policy = jsonencode({ # expect:iam
            Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
          })
        }
    ''', True),
)


# Native condition blocks must survive as data until ordered SID replacement
# and final grant classification. These labels do not evaluate AWS runtime
# condition truth. The expected-red baseline precedes condition lowering.
POLICY_CONDITION_CASES = (
    Case("iam_condition_restricted_policy_is_complete", '''
        data "aws_iam_policy_document" "restricted_condition" {
          statement {
            actions = ["s3:GetObject"]
            resources = ["arn:aws:s3:::example/*"]
            condition {
              test = "StringEquals"
              variable = "aws:PrincipalTag/team"
              values = ["blue"]
            }
          }
        }
        resource "aws_iam_policy" "restricted_condition" {
          policy = data.aws_iam_policy_document.restricted_condition.json
        }
    '''),
    Case("iam_condition_own_statement_replaced_exposes_grant", '''
        data "aws_iam_policy_document" "replaced_own_condition" {
          statement {
            sid = "Selected"
            actions = ["*"]
            resources = ["*"]
            condition {
              test = "Bool"
              variable = "aws:MultiFactorAuthPresent"
              values = ["true"]
            }
          }
          override_policy_documents = [jsonencode({
            Statement = [{ Sid = "Selected", Effect = "Allow", Action = "*", Resource = "*" }]
          })]
        }
        resource "aws_iam_policy" "replaced_own_condition" {
          policy = data.aws_iam_policy_document.replaced_own_condition.json # expect:iam
        }
    '''),
    Case("iam_condition_source_statement_replaced_exposes_grant", '''
        data "aws_iam_policy_document" "conditional_source" {
          statement {
            sid = "Selected"
            actions = ["*"]
            resources = ["*"]
            condition {
              test = "Bool"
              variable = "aws:MultiFactorAuthPresent"
              values = ["true"]
            }
          }
        }
        data "aws_iam_policy_document" "source_condition_replaced" {
          source_policy_documents = [data.aws_iam_policy_document.conditional_source.json]
          statement {
            sid = "Selected"
            actions = ["*"]
            resources = ["*"]
          }
        }
        resource "aws_iam_policy" "source_condition_replaced" {
          policy = data.aws_iam_policy_document.source_condition_replaced.json # expect:iam
        }
    '''),
    Case("iam_condition_later_override_removes_native_constraint", '''
        data "aws_iam_policy_document" "conditional_override" {
          statement {
            sid = "Selected"
            actions = ["*"]
            resources = ["*"]
            condition {
              test = "Bool"
              variable = "aws:MultiFactorAuthPresent"
              values = ["true"]
            }
          }
        }
        data "aws_iam_policy_document" "later_unconditional_override" {
          override_policy_documents = [
            data.aws_iam_policy_document.conditional_override.minified_json,
            jsonencode({ Statement = [{ Sid = "Selected", Effect = "Allow", Action = "*", Resource = "*" }] })
          ]
        }
        resource "aws_iam_policy" "later_unconditional_override" {
          policy = data.aws_iam_policy_document.later_unconditional_override.json # expect:iam
        }
    '''),
    Case("iam_condition_restricted_override_removes_broad_grant", '''
        data "aws_iam_policy_document" "restricted_override" {
          statement {
            sid = "Selected"
            actions = ["s3:GetObject"]
            resources = ["*"]
            condition {
              test = "StringEquals"
              variable = "aws:PrincipalTag/team"
              values = ["blue"]
            }
          }
        }
        data "aws_iam_policy_document" "restricted_final" {
          source_policy_documents = [jsonencode({
            Statement = [{ Sid = "Selected", Effect = "Allow", Action = "*", Resource = "*" }]
          })]
          override_policy_documents = [data.aws_iam_policy_document.restricted_override.json]
        }
        resource "aws_iam_policy" "restricted_final" {
          policy = data.aws_iam_policy_document.restricted_final.json
        }
    '''),
    Case("iam_condition_source_constraint_survives_composition", '''
        data "aws_iam_policy_document" "surviving_source" {
          statement {
            sid = "Conditional"
            actions = ["*"]
            resources = ["*"]
            condition {
              test = "Bool"
              variable = "aws:MultiFactorAuthPresent"
              values = ["true"]
            }
          }
        }
        data "aws_iam_policy_document" "surviving_composition" {
          source_policy_documents = [data.aws_iam_policy_document.surviving_source.json]
        }
        resource "aws_iam_policy" "surviving_composition" {
          policy = data.aws_iam_policy_document.surviving_composition.json
        }
    ''', True),
    Case("iam_condition_anonymous_statement_cannot_be_replaced", '''
        data "aws_iam_policy_document" "anonymous_condition" {
          statement {
            actions = ["*"]
            resources = ["*"]
            condition {
              test = "Bool"
              variable = "aws:MultiFactorAuthPresent"
              values = ["true"]
            }
          }
          override_policy_documents = [jsonencode({
            Statement = [{ Effect = "Allow", Action = "s3:GetObject", Resource = "*" }]
          })]
        }
        resource "aws_iam_policy" "anonymous_condition" {
          policy = data.aws_iam_policy_document.anonymous_condition.json
        }
    ''', True),
    Case("iam_condition_old_version_literal_values_are_supported", '''
        data "aws_iam_policy_document" "old_literal_condition" {
          version = "2008-10-17"
          statement {
            actions = ["s3:ListBucket"]
            resources = ["*"]
            condition {
              test = "StringLike"
              variable = "s3:prefix"
              values = [""]
            }
          }
        }
        resource "aws_iam_policy" "old_literal_condition" {
          policy = data.aws_iam_policy_document.old_literal_condition.json
        }
    '''),
    Case("iam_condition_own_version_controls_variable_substitution", '''
        data "aws_iam_policy_document" "old_condition_variables" {
          version = "2008-10-17"
          source_policy_documents = [jsonencode({ Version = "2012-10-17", Statement = [] })]
          statement {
            actions = ["s3:ListBucket"]
            resources = ["*"]
            condition {
              test = "StringLike"
              variable = "s3:prefix"
              values = ["home/&{aws:username}/*"]
            }
          }
        }
        resource "aws_iam_policy" "old_condition_variables" {
          policy = data.aws_iam_policy_document.old_condition_variables.json
        }
    ''', True),
    Case("iam_condition_unknown_values_cannot_be_hidden_by_replacement", '''
        data "aws_iam_policy_document" "unknown_condition_values" {
          statement {
            sid = "Selected"
            actions = ["*"]
            resources = ["*"]
            condition {
              test = "StringEquals"
              variable = "aws:PrincipalTag/team"
              values = var.teams
            }
          }
          override_policy_documents = [jsonencode({
            Statement = [{ Sid = "Selected", Effect = "Allow", Action = "*", Resource = "*" }]
          })]
        }
        resource "aws_iam_policy" "unknown_condition_values" {
          policy = data.aws_iam_policy_document.unknown_condition_values.json
        }
    ''', True),
    Case("iam_condition_unknown_operator_is_incomplete", '''
        data "aws_iam_policy_document" "unknown_condition_operator" {
          statement {
            actions = ["s3:GetObject"]
            resources = ["*"]
            condition {
              test = var.operator
              variable = "aws:PrincipalTag/team"
              values = ["blue"]
            }
          }
        }
        resource "aws_iam_policy" "unknown_condition_operator" {
          policy = data.aws_iam_policy_document.unknown_condition_operator.json
        }
    ''', True),
    Case("iam_condition_dynamic_blocks_are_incomplete", '''
        data "aws_iam_policy_document" "dynamic_conditions" {
          statement {
            actions = ["s3:GetObject"]
            resources = ["*"]
            dynamic "condition" {
              for_each = var.conditions
              content {
                test = "StringEquals"
                variable = "aws:PrincipalTag/team"
                values = ["blue"]
              }
            }
          }
        }
        resource "aws_iam_policy" "dynamic_conditions" {
          policy = data.aws_iam_policy_document.dynamic_conditions.json
        }
    ''', True),
    Case("iam_condition_does_not_admit_principal_statements", '''
        data "aws_iam_policy_document" "condition_and_principal" {
          statement {
            actions = ["*"]
            resources = ["*"]
            principals {
              type = "AWS"
              identifiers = ["*"]
            }
            condition {
              test = "Bool"
              variable = "aws:MultiFactorAuthPresent"
              values = ["true"]
            }
          }
        }
        resource "aws_iam_policy" "condition_and_principal" {
          policy = data.aws_iam_policy_document.condition_and_principal.json
        }
    ''', True),
    Case("iam_condition_scalar_values_are_incomplete", '''
        data "aws_iam_policy_document" "scalar_condition_values" {
          statement {
            actions = ["s3:GetObject"]
            resources = ["*"]
            condition {
              test = "StringEquals"
              variable = "aws:PrincipalTag/team"
              values = "blue"
            }
          }
        }
        resource "aws_iam_policy" "scalar_condition_values" {
          policy = data.aws_iam_policy_document.scalar_condition_values.json
        }
    ''', True),
    Case("iam_condition_missing_context_variable_is_incomplete", '''
        data "aws_iam_policy_document" "missing_condition_variable" {
          statement {
            actions = ["s3:GetObject"]
            resources = ["*"]
            condition {
              test = "StringEquals"
              values = ["blue"]
            }
          }
        }
        resource "aws_iam_policy" "missing_condition_variable" {
          policy = data.aws_iam_policy_document.missing_condition_variable.json
        }
    ''', True),
    Case("iam_condition_empty_operator_is_incomplete", '''
        data "aws_iam_policy_document" "empty_condition_operator" {
          statement {
            actions = ["s3:GetObject"]
            resources = ["*"]
            condition {
              test = ""
              variable = "aws:PrincipalTag/team"
              values = ["blue"]
            }
          }
        }
        resource "aws_iam_policy" "empty_condition_operator" {
          policy = data.aws_iam_policy_document.empty_condition_operator.json
        }
    ''', True),
    Case("iam_condition_empty_values_are_incomplete", '''
        data "aws_iam_policy_document" "empty_condition_values" {
          statement {
            actions = ["s3:GetObject"]
            resources = ["*"]
            condition {
              test = "StringEquals"
              variable = "aws:PrincipalTag/team"
              values = []
            }
          }
        }
        resource "aws_iam_policy" "empty_condition_values" {
          policy = data.aws_iam_policy_document.empty_condition_values.json
        }
    ''', True),
    Case("iam_condition_nested_unknown_block_is_incomplete", '''
        data "aws_iam_policy_document" "nested_condition_block" {
          statement {
            actions = ["s3:GetObject"]
            resources = ["*"]
            condition {
              test = "StringEquals"
              variable = "aws:PrincipalTag/team"
              values = ["blue"]
              unexpected {
                ignored = true
              }
            }
          }
        }
        resource "aws_iam_policy" "nested_condition_block" {
          policy = data.aws_iam_policy_document.nested_condition_block.json
        }
    ''', True),
    Case("iam_condition_child_cycle_keeps_independent_finding", '''
        locals {
          context = { values = ["true"], generated = data.aws_iam_policy_document.condition_cycle.json }
        }
        data "aws_iam_policy_document" "condition_cycle" {
          statement {
            actions = ["s3:GetObject"]
            resources = ["*"]
            condition {
              test = "Bool"
              variable = "aws:MultiFactorAuthPresent"
              values = local.context.values
            }
          }
        }
        resource "aws_iam_policy" "condition_cycle" {
          policy = data.aws_iam_policy_document.condition_cycle.json
        }
        resource "aws_iam_policy" "condition_cycle_control" {
          policy = jsonencode({ # expect:iam
            Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
          })
        }
    ''', True),
)


JSON_CASES = (
    JSONCase("tfjson_modern_public_ssh", '''
        {
          "resource": {
            "aws_vpc_security_group_ingress_rule": {
              "json_ssh": {
                "security_group_id": "sg-example",
                "cidr_ipv4": "0.0.0.0/0",
                "ip_protocol": "tcp",
                "from_port": 22,
                "to_port": 22
              }
            }
          }
        }
    ''', locations=(("network", 4, 7),)),
    JSONCase("tfjson_legacy_public_rdp", '''
        {
          "resource": {"aws_security_group_rule": {
            "json_rdp": {
              "type": "ingress",
              "security_group_id": "sg-example",
              "protocol": "tcp",
              "from_port": 3389,
              "to_port": 3389,
              "ipv6_cidr_blocks": ["::/0"]
            }
          }}
        }
    ''', locations=(("network", 3, 5),)),
    JSONCase("tfjson_restricted_ingress", '''
        {
          "resource": {"aws_vpc_security_group_ingress_rule": {
            "json_private": {
              "security_group_id": "sg-example",
              "cidr_ipv4": "10.0.0.0/8",
              "ip_protocol": "tcp",
              "from_port": 22,
              "to_port": 22
            }
          }}
        }
    '''),
    JSONCase("tfjson_public_bucket_acl", '''
        {
          "resource": {"aws_s3_bucket": {"json_public": {
            "bucket": "json-public-example",
            "acl": "public-read"
          }}}
        }
    ''', locations=(("storage", 4, 5),)),
    JSONCase("tfjson_bucket_reference_protection", '''
        {
          "resource": {
            "aws_s3_bucket": {"json_protected": {
              "bucket": "json-protected-example",
              "acl": "public-read"
            }},
            "aws_s3_bucket_public_access_block": {"json_protected": {
              "bucket": "${aws_s3_bucket.json_protected.id}",
              "ignore_public_acls": true
            }}
          }
        }
    '''),
    JSONCase("tfjson_bucket_ownership_conflict", '''
        {
          "resource": {
            "aws_s3_bucket": {"json_conflict": {
              "bucket": "json-conflict-example", "acl": "public-read"
            }},
            "aws_s3_bucket_ownership_controls": {"json_conflict": {
              "bucket": "${aws_s3_bucket.json_conflict.id}",
              "rule": {"object_ownership": "BucketOwnerEnforced"}
            }}
          }
        }
    ''', True),
    JSONCase("tfjson_provider_tls_typed_interpolation", '''
        {
          "locals": {"disable_tls": true},
          "provider": {"aws": {
            "insecure": "${local.disable_tls}"
          }}
        }
    ''', locations=(("tls", 4, 5),)),
    JSONCase("tfjson_provider_secure_control", '''
        {
          "provider": {"aws": {"insecure": false}}
        }
    '''),
    JSONCase("tfjson_provider_alias_static_traversal", '''
        {
          "terraform": {"required_providers": {
            "cloud": {"source": "hashicorp/aws"}
          }},
          "provider": {"cloud": {"alias": "east", "insecure": false}},
          "resource": {"aws_s3_bucket": {"json_alias": {
            "provider": "cloud.east",
            "bucket": "json-alias-example",
            "acl": "public-read"
          }}}
        }
    ''', locations=(("storage", 9, 5),)),
    JSONCase("tfjson_iam_generated_identity_policy", '''
        {
          "data": {"aws_iam_policy_document": {"json_admin": {
            "statement": {"actions": ["*"], "resources": ["*"]}
          }}},
          "resource": {"aws_iam_policy": {"json_admin": {
            "policy": "${data.aws_iam_policy_document.json_admin.json}"
          }}}
        }
    ''', locations=(("iam", 6, 5),)),
    JSONCase("tfjson_iam_statement_condition_and_override", '''
        {
          "locals": {"replacement": {
            "Statement": [{"Sid": "Selected", "Effect": "Allow", "Action": "*", "Resource": "*"}]
          }},
          "data": {"aws_iam_policy_document": {"json_conditions": {
            "statement": [{
              "sid": "Selected", "actions": ["*"], "resources": ["*"],
              "condition": [{"test": "Bool", "variable": "aws:MultiFactorAuthPresent", "values": ["true"]}]
            }],
            "override_policy_documents": ["${jsonencode(local.replacement)}"]
          }}},
          "resource": {"aws_iam_policy": {"json_conditions": {
            "policy": "${data.aws_iam_policy_document.json_conditions.minified_json}"
          }}}
        }
    ''', locations=(("iam", 13, 5),)),
    JSONCase("tfjson_iam_restricted_condition", '''
        {
          "data": {"aws_iam_policy_document": {"json_restricted": {
            "statement": {
              "actions": ["s3:GetObject"], "resources": ["*"],
              "condition": {"test": "StringEquals", "variable": "aws:PrincipalTag/team", "values": ["blue"]}
            }
          }}},
          "resource": {"aws_iam_policy": {"json_restricted": {
            "policy": "${data.aws_iam_policy_document.json_restricted.json}"
          }}}
        }
    '''),
    JSONCase("tfjson_iam_surviving_condition_is_incomplete", '''
        {
          "data": {"aws_iam_policy_document": {"json_conditional": {
            "statement": {
              "actions": ["*"], "resources": ["*"],
              "condition": {"test": "Bool", "variable": "aws:MultiFactorAuthPresent", "values": ["true"]}
            }
          }}},
          "resource": {"aws_iam_policy": {"json_conditional": {
            "policy": "${data.aws_iam_policy_document.json_conditional.json}"
          }}}
        }
    ''', True),
    JSONCase("tfjson_typed_list_and_number_interpolation", '''
        {
          "locals": {"ports": {"admin": 22}, "world": ["0.0.0.0/0"]},
          "resource": {"aws_security_group_rule": {
            "json_typed": {
              "type": "ingress", "security_group_id": "sg-example", "protocol": "tcp",
              "from_port": "${local.ports.admin}", "to_port": "${local.ports.admin}",
              "cidr_blocks": "${local.world}"
            }
          }}
        }
    ''', locations=(("network", 4, 5),)),
    JSONCase("tfjson_plain_reference_text_stays_literal", '''
        {
          "locals": {"acl": "public-read"},
          "resource": {"aws_s3_bucket": {"json_literal": {
            "bucket": "json-literal-example", "acl": "local.acl"
          }}}
        }
    '''),
    JSONCase("tfjson_mixed_template_is_explicitly_incomplete", '''
        {
          "locals": {"address": "0.0.0.0"},
          "resource": {"aws_vpc_security_group_ingress_rule": {"json_template": {
            "cidr_ipv4": "${local.address}/0", "ip_protocol": "tcp",
            "from_port": 22, "to_port": 22, "security_group_id": "sg-example"
          }}}
        }
    ''', True),
    JSONCase("tfjson_input_default_does_not_resolve_variable", '''
        {
          "variable": {"world": {"default": "0.0.0.0/0"}},
          "resource": {"aws_vpc_security_group_ingress_rule": {"json_variable": {
            "cidr_ipv4": "${var.world}", "ip_protocol": "tcp",
            "from_port": 22, "to_port": 22, "security_group_id": "sg-example"
          }}}
        }
    ''', True),
    JSONCase("tfjson_provider_reference_is_not_a_template", '''
        {
          "locals": {"binding": "aws"},
          "resource": {"aws_s3_bucket": {"json_binding": {
            "provider": "${local.binding}", "bucket": "json-binding-example", "acl": "public-read"
          }}}
        }
    ''', True),
    JSONCase("tfjson_terraform_provider_source_is_literal", '''
        {
          "locals": {"source": "hashicorp/aws"},
          "terraform": {"required_providers": {"aws": {"source": "${local.source}"}}},
          "resource": {"aws_s3_bucket": {"json_literal_source": {
            "bucket": "json-literal-source-example", "acl": "public-read"
          }}}
        }
    ''', True),
    JSONCase("tfjson_provider_alias_is_literal", '''
        {
          "locals": {"alias": "east"},
          "provider": {"aws": {"alias": "${local.alias}", "insecure": true}}
        }
    ''', True),
    JSONCase("tfjson_body_comment_is_not_configuration", '''
        {
          "//": {"resource": {"aws_s3_bucket": {"fake": {"acl": "public-read"}}}},
          "provider": {"aws": {
            "//": "insecure=true is documentation, not an argument",
            "insecure": false
          }}
        }
    '''),
    JSONCase("tfjson_expression_comment_key_is_not_discarded", '''
        {
          "locals": {"policy": {
            "//": "This is an expression field, not a body comment",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
          }},
          "resource": {"aws_iam_policy": {"json_comment_field": {
            "policy": "${jsonencode(local.policy)}"
          }}}
        }
    ''', True),
    JSONCase("tfjson_duplicate_block_properties_are_preserved", '''
        {
          "provider": {"aws": {"alias": "first",
            "insecure": true
          }},
          "provider": {"aws": {"alias": "second",
            "insecure": true
          }}
        }
    ''', locations=(("tls", 3, 5), ("tls", 6, 5))),
    JSONCase("tfjson_root_label_and_body_arrays", '''
        [
          {"provider": [{"aws": [
            {"alias": "array_first", "insecure": false},
            {"alias": "array_second",
             "insecure": true}
          ]}]},
          {"resource": [{"aws_vpc_security_group_ingress_rule": [
            {"json_array_ssh": {
              "cidr_ipv4": "0.0.0.0/0", "ip_protocol": "tcp",
              "from_port": 22, "to_port": 22, "security_group_id": "sg-example"
            }}
          ]}]}
        ]
    ''', locations=(("tls", 5, 6), ("network", 8, 6))),
    JSONCase("tfjson_duplicate_attribute_is_incomplete", '''
        {
          "provider": {"aws": {"insecure": true, "insecure": false}}
        }
    ''', True),
    JSONCase("tfjson_duplicate_expression_key_is_incomplete", '''
        {
          "locals": {"settings": {"acl": "public-read", "acl": "private"}},
          "resource": {"aws_s3_bucket": {"json_duplicate": {
            "bucket": "json-duplicate-example", "acl": "${local.settings.acl}"
          }}}
        }
    ''', True),
    JSONCase("tfjson_evaluated_expression_key_collision_is_incomplete", '''
        {
          "locals": {"key": "acl", "settings": {"${local.key}": "public-read", "acl": "private"}},
          "resource": {"aws_s3_bucket": {"json_collision": {
            "bucket": "json-collision-example", "acl": "${local.settings.acl}"
          }}}
        }
    ''', True),
    JSONCase("tfjson_nonintegral_number_cannot_round_to_admin_port", '''
        {
          "resource": {"aws_vpc_security_group_ingress_rule": {"json_precision": {
            "cidr_ipv4": "0.0.0.0/0", "ip_protocol": "tcp",
            "from_port": 22.00000000000000000001, "to_port": 22,
            "security_group_id": "sg-example"
          }}}
        }
    ''', True),
    JSONCase("tfjson_attribute_ingress_is_not_a_nested_block", '''
        {
          "resource": {"aws_security_group": {"json_attribute_ingress": {
            "ingress": [{"protocol": "tcp", "from_port": 22, "to_port": 22,
                         "cidr_blocks": ["0.0.0.0/0"]}]
          }}}
        }
    ''', True),
    JSONCase("tfjson_empty_attribute_ingress", '''
        {
          "resource": {"aws_security_group": {"json_empty_ingress": {"ingress": []}}}
        }
    '''),
    JSONCase("tfjson_dynamic_relevant_statement_is_incomplete", '''
        {
          "data": {"aws_iam_policy_document": {"json_dynamic": {
            "dynamic": {"statement": {"for_each": "${var.statements}",
              "content": {"actions": ["*"], "resources": ["*"]}
            }}
          }}},
          "resource": {"aws_iam_policy": {"json_dynamic": {
            "policy": "${data.aws_iam_policy_document.json_dynamic.json}"
          }}}
        }
    ''', True),
    JSONCase("tfjson_invalid_block_shape_is_incomplete", '''
        {"resource": {"aws_iam_policy": {"policy": "not a labeled block body"}}}
    ''', True),
    JSONCase("tfjson_trailing_comma_is_incomplete", '''
        {"provider": {"aws": {"insecure": false,}}}
    ''', True),
    JSONCase("tfjson_non_json_constant_is_incomplete", '''
        {"provider": {"aws": {"insecure": NaN}}}
    ''', True),
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

    def test_iam_composed_selected_siblings_and_module_isolation(self):
        analyzer = importlib.import_module("ubs_core.hcl_scan")
        consumer = Case("main", '''
            resource "aws_iam_policy" "selected_composition" {
              policy = local.composed_json # expect:iam
            }
        ''')
        composition = Case("composition", '''
            locals {
              composed_json = data.aws_iam_policy_document.selected_composition.json
            }
            data "aws_iam_policy_document" "selected_composition" {
              source_policy_documents = [data.aws_iam_policy_document.sibling_source.json]
            }
        ''')
        source = Case("source", '''
            data "aws_iam_policy_document" "sibling_source" {
              statement {
                actions = ["*"]
                resources = ["*"]
              }
            }
        ''')
        directory = self.materialize((consumer, composition, source), "iam-composed-selected-module")
        paths = {str(directory / case.filename): case.source for case in (consumer, composition)}
        other = directory / "child-module"
        other.mkdir()
        (other / source.filename).write_text(source.source, encoding="utf-8")
        scenarios = (
            ("selected-source", {**paths, str(directory / source.filename): source.source}, False),
            ("source-not-selected", paths, True),
            ("source-in-child-module", {**paths, str(other / source.filename): source.source}, True),
        )
        for name, sources, partial in scenarios:
            with self.subTest(selection=name):
                records, errors = analyzer.analyze_sources(sources)
                actual = sorted((row["path"], row["rule"], row["line"], row["col"]) for row in records)
                expected = [] if partial else [(str(directory / consumer.filename), rule, line, col)
                                               for rule, line, col in consumer.expected]
                (directory / (name + ".json")).write_text(json.dumps({
                    **self.identity, "selected_sources": list(sources), "expected": expected,
                    "actual": actual, "findings": records, "errors": errors, "incomplete": partial,
                    "analyzer_sha256": hashlib.sha256(Path(analyzer.__file__).read_bytes()).hexdigest(),
                }, indent=2) + "\n", encoding="utf-8")
                self.assertEqual(bool(errors), partial, (sources, records, errors))
                self.assertEqual(actual, expected, (sources, records, errors))

    def test_iam_composed_version_cannot_be_downgraded(self):
        analyzer = importlib.import_module("ubs_core.hcl_scan")
        case = Case("iam_composed_version", '''
            data "aws_iam_policy_document" "version_order" {
              version = "2008-10-17"
              source_policy_documents = [jsonencode({ Version = "2012-10-17", Statement = [
                { Effect = "Allow", Action = "*", Resource = "*" }
              ] })]
              override_policy_documents = [jsonencode({ Version = "2008-10-17", Statement = [] })]
            }
            resource "aws_iam_policy" "version_order" {
              policy = data.aws_iam_policy_document.version_order.json # expect:iam
            }
        ''')
        directory = self.materialize((case,), case.name)
        source = str(directory / case.filename)
        module = analyzer.Module({source: case.source}, set(analyzer.RULES))
        records, errors = module.run()
        actual = sorted((row["rule"], row["line"], row["col"]) for row in records)
        # Observe the generated value that the real identity-policy consumer
        # receives. Finding counts alone cannot reveal a version downgrade.
        generated = module.values.attribute(module.resources[0], "policy")
        self.assertIsInstance(generated, str, (records, errors, generated))
        policy = json.loads(generated)
        (directory / "receipt.json").write_text(json.dumps({
            **self.identity, "expected": case.expected, "actual": actual,
            "findings": records, "errors": errors, "generated_policy": policy,
            "analyzer_sha256": hashlib.sha256(Path(analyzer.__file__).read_bytes()).hexdigest(),
        }, indent=2) + "\n", encoding="utf-8")
        self.assertEqual(errors, [], (records, errors))
        self.assertEqual(actual, case.expected, (records, errors))
        self.assertEqual(policy["Version"], "2012-10-17", policy)

    def test_iam_composed_shared_documents_obey_resource_budgets(self):
        analyzer = importlib.import_module("ubs_core.hcl_scan")
        # These sources are only a few KiB. Repeated references expand the
        # intermediate anonymous statement list; named override statements
        # keep the result small while still requiring repeated decode work.
        scenarios = (("source_policy_documents", False, "document"),
                     ("override_policy_documents", False, "document"),
                     ("override_policy_documents", True, "context"))
        for field, named, budget in scenarios:
            with self.subTest(field=field, named=named, budget=budget):
                statement = {"Effect": "Allow", "Action": "*", "Resource": ["*", "arn:aws:s3:::example/" + "a" * 180]}
                if named:
                    statement["Sid"] = "Selected"
                document = json.dumps({"Statement": [statement]}, separators=(",", ":"))
                name = f"iam_composed_{field}_{budget}_budget"
                code = ('locals { document = ' + json.dumps(document) + ' }\n'
                        'data "aws_iam_policy_document" "repeated" {\n'
                        f'  {field} = [' + ", ".join(["local.document"] * 32) + ']\n}\n'
                        'resource "aws_iam_policy" "repeated" {\n'
                        '  policy = data.aws_iam_policy_document.repeated.json # expect:iam\n}\n')
                control = Case(name, code)
                self.check_native(control)
                limited = Case(name + "_limited", code.replace(" # expect:iam", ""), True)
                directory = self.materialize((limited,), limited.name)
                source = directory / limited.filename
                caps = {"MAX_POLICY_BYTES": 1024} if budget == "document" else {
                    "MAX_POLICY_BYTES": 1024, "MAX_CONTEXT_BYTES": len(limited.source.encode("utf-8")) + 64,
                }
                with mock.patch.multiple(analyzer, **caps):
                    records, errors = analyzer.analyze_source(limited.source, str(source))
                (directory / "receipt.json").write_text(json.dumps({
                    **self.identity, "findings": records, "errors": errors, "limits": caps,
                    "source_bytes": len(limited.source.encode("utf-8")), "shared_document_bytes": len(document),
                    "references": 32,
                    "analyzer_sha256": hashlib.sha256(Path(analyzer.__file__).read_bytes()).hexdigest(),
                }, indent=2) + "\n", encoding="utf-8")
                self.assertEqual(records, [], (records, errors))
                self.assertTrue(any("budget" in error.lower() for error in errors), (records, errors))

    def test_iam_native_condition_grouping_and_variable_encoding(self):
        analyzer = importlib.import_module("ubs_core.hcl_scan")
        cases = (
            (Case("iam_native_condition_groups", '''
                data "aws_iam_policy_document" "groups" {
                  statement {
                    actions = ["s3:GetObject"]
                    resources = ["*"]
                    condition {
                      test = "StringEquals"
                      variable = "aws:PrincipalTag/team"
                      values = ["blue"]
                    }
                    condition {
                      test = "StringEquals"
                      variable = "aws:PrincipalTag/team"
                      values = ["green", "red"]
                    }
                    condition {
                      test = "StringEquals"
                      variable = "aws:PrincipalTag/team"
                      values = ["blue"]
                    }
                    condition {
                      test = "StringEquals"
                      variable = "aws:PrincipalTag/project"
                      values = ["demo"]
                    }
                    condition {
                      test = "Bool"
                      variable = "aws:MultiFactorAuthPresent"
                      values = ["true"]
                    }
                  }
                }
                resource "aws_iam_policy" "groups" {
                  policy = data.aws_iam_policy_document.groups.json
                }
            '''), {"StringEquals": {"aws:PrincipalTag/team": ["blue", "green", "red"],
                                   "aws:PrincipalTag/project": "demo"},
                   "Bool": {"aws:MultiFactorAuthPresent": "true"}}),
            (Case("iam_native_condition_substitution", '''
                locals {
                  condition = { operator = "StringLike", context = "s3:prefix", prefixes = ["home/&{aws:username}/*", ""] }
                }
                data "aws_iam_policy_document" "substitution" {
                  statement {
                    actions = ["s3:ListBucket"]
                    resources = ["*"]
                    condition {
                      test = local.condition.operator
                      variable = local.condition.context
                      values = local.condition.prefixes
                    }
                  }
                }
                resource "aws_iam_policy" "substitution" {
                  policy = data.aws_iam_policy_document.substitution.minified_json
                }
            '''), {"StringLike": {"s3:prefix": ["", "home/${aws:username}/*"]}}),
        )
        for case, expected in cases:
            with self.subTest(case=case.name):
                directory = self.materialize((case,), case.name)
                source = str(directory / case.filename)
                module = analyzer.Module({source: case.source}, set(analyzer.RULES))
                records, errors = module.run()
                generated = module.values.attribute(module.resources[0], "policy")
                policy = json.loads(generated) if isinstance(generated, str) else None
                (directory / "receipt.json").write_text(json.dumps({
                    **self.identity, "findings": records, "errors": errors, "generated_policy": policy,
                    "expected_condition": expected,
                    "analyzer_sha256": hashlib.sha256(Path(analyzer.__file__).read_bytes()).hexdigest(),
                }, indent=2) + "\n", encoding="utf-8")
                self.assertEqual((records, errors), ([], []), (records, errors))
                self.assertIsNotNone(policy, generated)
                actual = policy["Statement"][0]["Condition"]
                # TypeSet block iteration need not follow source order. OR
                # values retain their exact membership and scalar/list shape.
                normalized = {operator: {name: sorted(value) if isinstance(value, list) else value
                                         for name, value in terms.items()}
                              for operator, terms in actual.items()}
                self.assertEqual(normalized, expected, policy)

    def test_iam_native_conditions_use_only_selected_module_locals(self):
        analyzer = importlib.import_module("ubs_core.hcl_scan")
        consumer = Case("main", '''
            data "aws_iam_policy_document" "local_condition" {
              statement {
                sid = "Selected"
                actions = ["*"]
                resources = ["*"]
                condition {
                  test = local.condition.operator
                  variable = local.condition.context
                  values = local.condition.values
                }
              }
              override_policy_documents = [jsonencode({
                Statement = [{ Sid = "Selected", Effect = "Allow", Action = "*", Resource = "*" }]
              })]
            }
            resource "aws_iam_policy" "local_condition" {
              policy = data.aws_iam_policy_document.local_condition.json # expect:iam
            }
        ''')
        settings = Case("settings", '''
            locals {
              condition = { operator = "Bool", context = "aws:MultiFactorAuthPresent", values = ["true"] }
            }
        ''')
        directory = self.materialize((consumer, settings), "iam-native-condition-module")
        source = str(directory / consumer.filename)
        child = directory / "child-module"
        child.mkdir()
        (child / settings.filename).write_text(settings.source, encoding="utf-8")
        for name, context, partial in (
            ("selected-settings", {str(directory / settings.filename): settings.source}, False),
            ("missing-settings", {}, True),
            ("different-module", {str(child / settings.filename): settings.source}, True),
        ):
            with self.subTest(selection=name):
                records, errors = analyzer.analyze_sources({source: consumer.source, **context})
                actual = sorted((row["path"], row["rule"], row["line"], row["col"]) for row in records)
                expected = [] if partial else [(source, rule, line, col) for rule, line, col in consumer.expected]
                (directory / (name + ".json")).write_text(json.dumps({
                    **self.identity, "expected": expected, "actual": actual, "findings": records,
                    "errors": errors, "incomplete": partial,
                    "analyzer_sha256": hashlib.sha256(Path(analyzer.__file__).read_bytes()).hexdigest(),
                }, indent=2) + "\n", encoding="utf-8")
                self.assertEqual(bool(errors), partial, (records, errors))
                self.assertEqual(actual, expected, (records, errors))

    def test_iam_native_condition_shared_values_are_bounded_before_encoding(self):
        analyzer = importlib.import_module("ubs_core.hcl_scan")
        value = "a" * 180 + "/&{aws:username}/*"
        control = Case("iam_native_condition_expansion", '''
            locals {
              prefix = %s
            }
            data "aws_iam_policy_document" "condition_expansion" {
              statement {
                actions = ["s3:GetObject"]
                resources = ["*"]
                condition {
                  test = "StringLike"
                  variable = "s3:prefix"
                  values = [local.prefix, local.prefix, local.prefix, local.prefix]
                }
              }
            }
            resource "aws_iam_policy" "condition_expansion" {
              policy = data.aws_iam_policy_document.condition_expansion.json
            }
        ''' % json.dumps(value))
        with self.subTest(budget="normal"):
            self.check_native(control)
        case = Case(control.name + "_limited", control.code, True)
        directory = self.materialize((case,), case.name)
        source = directory / case.filename
        with mock.patch.object(analyzer, "MAX_POLICY_BYTES", 512), \
                mock.patch.object(analyzer.json.JSONEncoder, "iterencode",
                                  side_effect=AssertionError("oversized condition values reached the serializer")):
            records, errors = analyzer.analyze_source(case.source, str(source))
        (directory / "receipt.json").write_text(json.dumps({
            **self.identity, "findings": records, "errors": errors, "per_document_limit": 512,
            "analyzer_sha256": hashlib.sha256(Path(analyzer.__file__).read_bytes()).hexdigest(),
        }, indent=2) + "\n", encoding="utf-8")
        self.assertEqual(records, [], (records, errors))
        self.assertTrue(any("budget" in error.lower() for error in errors), (records, errors))

    def test_iam_native_condition_shared_empty_strings_have_an_expansion_budget(self):
        analyzer = importlib.import_module("ubs_core.hcl_scan")
        conditions = "\n".join('''
                    condition {
                      test = "StringEquals"
                      variable = "aws:PrincipalTag/context%d"
                      values = local.empty_values
                    }
        ''' % index for index in range(8))
        control = Case("iam_native_condition_shared_empty_values", '''
            locals {
              empty_values = %s
            }
            data "aws_iam_policy_document" "empty_conditions" {
              statement {
                actions = ["s3:GetObject"]
                resources = ["*"]
                %s
              }
            }
            resource "aws_iam_policy" "empty_conditions" {
              policy = data.aws_iam_policy_document.empty_conditions.json
            }
        ''' % (json.dumps([""] * 32), conditions))
        with self.subTest(budget="normal"):
            self.check_native(control)
        case = Case(control.name + "_limited", control.code, True)
        directory = self.materialize((case,), case.name)
        with mock.patch.object(analyzer, "MAX_POLICY_BYTES", 512), \
                mock.patch.object(analyzer.json.JSONEncoder, "iterencode",
                                  side_effect=AssertionError("shared empty condition strings reached the serializer")):
            records, errors = analyzer.analyze_source(case.source, str(directory / case.filename))
        (directory / "receipt.json").write_text(json.dumps({
            **self.identity, "findings": records, "errors": errors, "per_document_limit": 512,
            "shared_values": 32, "condition_references": 8,
            "analyzer_sha256": hashlib.sha256(Path(analyzer.__file__).read_bytes()).hexdigest(),
        }, indent=2) + "\n", encoding="utf-8")
        self.assertEqual(records, [], (records, errors))
        self.assertTrue(any("budget" in error.lower() for error in errors), (records, errors))

    def test_tfjson_mixed_syntax_context_and_module_isolation(self):
        analyzer = importlib.import_module("ubs_core.hcl_scan")
        consumer = JSONCase("main", '''
            {"resource": {"aws_s3_bucket": {"json_mixed": {
              "bucket": "json-mixed-example",
              "acl": "${local.acl}"
            }}}}
        ''', locations=(("storage", 3, 3),))
        settings = Case("settings", 'locals { acl = "public-read" }')
        protector = Case("protection", '''
            resource "aws_s3_bucket_public_access_block" "json_mixed" {
              bucket = aws_s3_bucket.json_mixed.id
              ignore_public_acls = true
            }
        ''')
        directory = self.materialize((consumer, settings, protector), "tfjson-mixed-module")
        sources = {str(directory / case.filename): case.source for case in (consumer, settings, protector)}
        child = directory / "child-module"
        child.mkdir()
        child_settings = child / settings.filename
        child_settings.write_text(settings.source, encoding="utf-8")
        scenarios = (
            ("selected-protection", sources, [], False),
            ("without-protection", {path: source for path, source in sources.items()
                                    if path != str(directory / protector.filename)}, consumer.expected, False),
            ("unselected-local", {str(directory / consumer.filename): consumer.source}, [], True),
            ("nested-module-local", {str(directory / consumer.filename): consumer.source,
                                     str(child_settings): settings.source}, [], True),
        )
        for name, selected, expected, partial in scenarios:
            with self.subTest(selection=name):
                records, errors = analyzer.analyze_sources(selected)
                actual = sorted((row["rule"], row["line"], row["col"]) for row in records)
                (directory / (name + ".json")).write_text(json.dumps({
                    **self.identity, "selected_files": sorted(selected), "expected": expected,
                    "actual": actual, "findings": records, "errors": errors,
                    "analyzer_sha256": hashlib.sha256(Path(analyzer.__file__).read_bytes()).hexdigest(),
                }, indent=2) + "\n", encoding="utf-8")
                self.assertEqual((actual, bool(errors)), (expected, partial), (records, errors))

    def test_tfjson_json_local_objects_supply_native_policy_and_keep_cycles(self):
        analyzer = importlib.import_module("ubs_core.hcl_scan")
        consumer = Case("native_consumer", '''
            resource "aws_iam_policy" "from_json" {
              policy = jsonencode(local.json_identity) # expect:iam
            }
        ''')
        settings = JSONCase("json_settings", '''
            {"locals": {"json_identity": {
              "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
            }}}
        ''')
        directory = self.materialize((consumer, settings), "tfjson-native-consumer")
        variants = (
            ("literal", settings.source, consumer.expected, False),
            ("duplicate-cross-syntax", settings.source, [], True),
            ("hidden-cycle", '''{"locals": {"json_identity": {
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
                "unused": "${local.json_identity}"
            }}}''', [], True),
        )
        for name, context, expected, partial in variants:
            with self.subTest(context=name):
                selected = {str(directory / consumer.filename): consumer.source,
                            str(directory / settings.filename): context}
                if name == "duplicate-cross-syntax":
                    extra = directory / "duplicate.tf"
                    selected[str(extra)] = 'locals { json_identity = {} }\n'
                    extra.write_text(selected[str(extra)], encoding="utf-8")
                (directory / (name + ".source.txt")).write_text(context, encoding="utf-8")
                records, errors = analyzer.analyze_sources(selected)
                actual = sorted((row["rule"], row["line"], row["col"]) for row in records)
                (directory / (name + ".json")).write_text(json.dumps({
                    **self.identity, "selected_files": sorted(selected), "expected": expected,
                    "actual": actual, "findings": records, "errors": errors,
                    "analyzer_sha256": hashlib.sha256(Path(analyzer.__file__).read_bytes()).hexdigest(),
                }, indent=2) + "\n", encoding="utf-8")
                self.assertEqual((actual, bool(errors)), (expected, partial), (records, errors))

    def test_tfjson_source_context_token_and_nesting_budgets(self):
        analyzer = importlib.import_module("ubs_core.hcl_scan")
        case = next(case for case in JSON_CASES if case.name == "tfjson_modern_public_ssh")
        directory = self.materialize((case,), "tfjson-budget-boundaries")
        for name, limit in (("MAX_SOURCE_BYTES", len(case.source.encode("utf-8")) - 1),
                            ("MAX_CONTEXT_BYTES", len(case.source.encode("utf-8")) - 1),
                            ("MAX_TOKENS", 12), ("MAX_NESTING", 3)):
            with self.subTest(budget=name):
                with mock.patch.object(analyzer, name, limit):
                    records, errors = analyzer.analyze_source(case.source, str(directory / case.filename))
                (directory / (name + ".json")).write_text(json.dumps({
                    **self.identity, "findings": records, "errors": errors, "limit": {name: limit},
                    "analyzer_sha256": hashlib.sha256(Path(analyzer.__file__).read_bytes()).hexdigest(),
                }, indent=2) + "\n", encoding="utf-8")
                self.assertEqual(records, [], (records, errors))
                self.assertTrue(any("budget" in error.lower() for error in errors), (records, errors))

    def test_bucket_identity_literals_and_traversals_in_native_and_json(self):
        native_literal = Case("bucket_native_literal_identity", '''
            resource "aws_s3_bucket" "actual" {
              bucket = "actual-identity-example"
              acl = "public-read" # expect:storage
            }
            resource "aws_s3_bucket_public_access_block" "different_bucket" {
              bucket = "aws_s3_bucket.actual.id"
              ignore_public_acls = true
            }
        ''')
        native_reference = Case("bucket_native_traversal_identity", native_literal.code.replace(
            'bucket = "aws_s3_bucket.actual.id"', 'bucket = aws_s3_bucket.actual.id').replace(" # expect:storage", ""))
        json_literal = JSONCase("bucket_json_literal_identity", '''
            {
              "resource": {
                "aws_s3_bucket": {"actual": {
                  "bucket": "actual-identity-example",
                  "acl": "public-read"
                }},
                "aws_s3_bucket_public_access_block": {"different_bucket": {
                  "bucket": "aws_s3_bucket.actual.id",
                  "ignore_public_acls": true
                }}
              }
            }
        ''', locations=(("storage", 5, 7),))
        json_reference = JSONCase("bucket_json_traversal_identity", json_literal.code.replace(
            '"bucket": "aws_s3_bucket.actual.id"', '"bucket": "${aws_s3_bucket.actual.id}"'))
        native_acl_literal = Case("acl_native_literal_identity", '''
            resource "aws_s3_bucket" "actual" {
              bucket = "actual-identity-example"
            }
            resource "aws_s3_bucket_acl" "different_bucket" {
              bucket = "aws_s3_bucket.actual.id"
              acl = "public-read" # expect:storage
            }
            resource "aws_s3_bucket_public_access_block" "actual" {
              bucket = aws_s3_bucket.actual.id
              ignore_public_acls = true
            }
        ''')
        native_acl_reference = Case("acl_native_traversal_identity", native_acl_literal.code.replace(
            'bucket = "aws_s3_bucket.actual.id"', 'bucket = aws_s3_bucket.actual.id').replace(" # expect:storage", ""))
        json_acl_literal = JSONCase("acl_json_literal_identity", '''
            {
              "resource": {
                "aws_s3_bucket": {"actual": {"bucket": "actual-identity-example"}},
                "aws_s3_bucket_acl": {"different_bucket": {
                  "bucket": "aws_s3_bucket.actual.id",
                  "acl": "public-read"
                }},
                "aws_s3_bucket_public_access_block": {"actual": {
                  "bucket": "${aws_s3_bucket.actual.id}",
                  "ignore_public_acls": true
                }}
              }
            }
        ''', locations=(("storage", 6, 7),))
        json_acl_reference = JSONCase("acl_json_traversal_identity", json_acl_literal.code.replace(
            '"bucket": "aws_s3_bucket.actual.id"', '"bucket": "${aws_s3_bucket.actual.id}"'))
        for case in (native_literal, native_reference, json_literal, json_reference,
                     native_acl_literal, native_acl_reference, json_acl_literal, json_acl_reference):
            with self.subTest(case=case.name):
                self.check_native(case)

    def test_tfjson_single_interpolation_precision_and_comment_boundaries(self):
        precise = JSONCase("tfjson_interpolation_precision", '''
            {
              "resource": {"aws_vpc_security_group_ingress_rule": {
                "json_interpolation": {
                  "cidr_ipv4": "0.0.0.0/0", "ip_protocol": "tcp",
                  "from_port": "${22.00000000000000000001}", "to_port": 22,
                  "security_group_id": "sg-example"
                }
              }}
            }
        ''', True)
        integral = JSONCase("tfjson_interpolation_integral_control", precise.code.replace(
            "${22.00000000000000000001}", "${22.0}"), locations=(("network", 3, 5),))
        unterminated = JSONCase("tfjson_interpolation_closing_brace_is_commented", '''
            {
              "provider": {"aws": {
                "insecure": "${false #}"
              }}
            }
        ''', True)
        valid_comment = JSONCase("tfjson_interpolation_closes_after_comment", r'''
            {
              "provider": {"aws": {
                "insecure": "${true # comment\n}"
              }}
            }
        ''', locations=(("tls", 3, 5),))
        for case in (precise, integral, unterminated, valid_comment):
            with self.subTest(case=case.name):
                self.check_native(case)

    def test_tfjson_composed_local_depth_keeps_independent_finding(self):
        # Every source value is shallow, but following the selected local
        # chain composes 960 levels. Its final leaf is a valid private ACL;
        # analysis exhaustion must retain the preceding independent finding.
        declarations = {}
        for index in range(40):
            value = "${local.x%d}" % (index + 1) if index < 39 else "private"
            for _ in range(24):
                value = {"v": value}
            declarations["x%d" % index] = value
        case = JSONCase("tfjson_composed_local_depth", '''
            {
              "locals": %s,
              "resource": {"aws_s3_bucket": {
                "independent": {
                  "bucket": "independent-json-depth-example",
                  "acl": "public-read"
                },
                "private_at_depth": {
                  "bucket": "private-json-depth-example",
                  "acl": "${local.x0%s}"
                }
              }}
            }
        ''' % (json.dumps(declarations, separators=(",", ":")), ".v" * (40 * 24)),
            True, locations=(("storage", 6, 7),))
        self.check_native(case)


def native_test(case):
    def run(self):
        self.check_native(case)
    return run


for _case in CASES + REVIEW_CASES + IAM_CASES + TLS_CASES + POLICY_DOCUMENT_CASES + POLICY_COMPOSITION_CASES + POLICY_CONDITION_CASES + JSON_CASES:
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
        (directory / "example.json").write_text('{"not": "Terraform configuration"}\n', encoding="utf-8")
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

    def test_iam_composed_public_json_sarif(self):
        cases_by_name = {case.name: case for case in POLICY_COMPOSITION_CASES}
        cases = tuple(cases_by_name[name] for name in (
            "iam_composed_source_only_grant", "iam_composed_last_override_restricts",
            "iam_composed_absent_sid_is_not_overridden", "iam_composed_replaced_condition_no_longer_constrains_grant"))
        directory = self.materialize(cases, "iam-composed-formats")
        for mode in ("module-json", "module-sarif", "json", "sarif"):
            with self.subTest(mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, cases)

    def test_iam_composed_cache_tracks_source_and_override_changes(self):
        consumer = Case("main", '''
            resource "aws_iam_policy" "cached_composition" {
              policy = data.aws_iam_policy_document.cached_composition.json
            }
        ''')
        composition = Case("composition", '''
            data "aws_iam_policy_document" "cached_composition" {
              source_policy_documents = [data.aws_iam_policy_document.cached_source.json]
              override_policy_documents = [data.aws_iam_policy_document.cached_override.minified_json]
            }
        ''')
        source = Case("source", '''
            data "aws_iam_policy_document" "cached_source" {
              statement {
                sid = "Source"
                actions = ["s3:GetObject"]
                resources = ["*"]
              }
            }
        ''')
        override = Case("override", '''
            data "aws_iam_policy_document" "cached_override" {
              statement {
                sid = "Override"
                actions = ["s3:GetObject"]
                resources = ["*"]
              }
            }
        ''')
        directory = self.materialize((consumer, composition, source, override), "iam-composed-cache")
        for attempt in range(2):
            with self.subTest(state="restricted-" + str(attempt)):
                self.assert_report(*self.execute(directory, cached=True), "json",
                                   (consumer, composition, source, override))
        exposed = Case(consumer.name, consumer.code, locations=(("iam", 2, 3),))
        for selected in (source, override):
            changed = Case(selected.name, selected.code.replace('"s3:GetObject"', '"*"'))
            path = directory / changed.filename
            path.write_text(changed.source, encoding="utf-8")
            cases = (exposed, composition,
                     changed if selected is source else source,
                     changed if selected is override else override)
            with self.subTest(state="broadened-" + selected.name):
                self.assert_report(*self.execute(directory, cached=True), "json", cases)
            path.write_text(selected.source, encoding="utf-8")
            with self.subTest(state="restricted-again-" + selected.name):
                self.assert_report(*self.execute(directory, cached=True), "json",
                                   (consumer, composition, source, override))

    def test_iam_native_conditions_public_formats_and_partial_retention(self):
        cases_by_name = {case.name: case for case in POLICY_CONDITION_CASES}
        cases = tuple(cases_by_name[name] for name in (
            "iam_condition_restricted_policy_is_complete",
            "iam_condition_own_statement_replaced_exposes_grant",
            "iam_condition_source_statement_replaced_exposes_grant",
            "iam_condition_later_override_removes_native_constraint"))
        directory = self.materialize(cases, "iam-native-condition-formats")
        for mode in ("module-json", "module-sarif", "json", "sarif"):
            with self.subTest(mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, cases)
        partial = (cases_by_name["iam_condition_source_constraint_survives_composition"],
                   cases_by_name["iam_condition_own_statement_replaced_exposes_grant"])
        directory = self.materialize(partial, "iam-native-condition-partial")
        for mode in ("json", "sarif"):
            with self.subTest(partial_mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, partial, partial=True)

    def test_iam_native_conditions_cache_tracks_selected_context(self):
        consumer = Case("main", '''
            data "aws_iam_policy_document" "cached_conditions" {
              source_policy_documents = [data.aws_iam_policy_document.cached_condition_source.json]
              override_policy_documents = [data.aws_iam_policy_document.cached_condition_override.json]
            }
            resource "aws_iam_policy" "cached_conditions" {
              policy = data.aws_iam_policy_document.cached_conditions.json
            }
        ''')
        source = Case("source", '''
            data "aws_iam_policy_document" "cached_condition_source" {
              statement {
                sid = "Selected"
                actions = ["*"]
                resources = ["*"]
              }
            }
        ''')
        override = Case("override", '''
            data "aws_iam_policy_document" "cached_condition_override" {
              statement {
                sid = local.override_sid
                actions = ["s3:GetObject"]
                resources = ["*"]
                condition {
                  test = "StringEquals"
                  variable = "aws:PrincipalTag/environment"
                  values = local.condition_values
                }
              }
            }
        ''')
        settings = Case("settings", '''
            locals {
              override_sid = "Selected"
              condition_values = ["production"]
            }
        ''')
        directory = self.materialize((consumer, source, override, settings), "iam-native-condition-cache")
        for attempt in range(2):
            with self.subTest(state="restricted-" + str(attempt)):
                self.assert_report(*self.execute(directory, cached=True), "json",
                                   (consumer, source, override, settings))
        changed = Case(settings.name, '''
            locals {
              override_sid = "Different"
              condition_values = ["production"]
            }
        ''')
        settings_path = directory / settings.filename
        settings_path.write_text(changed.source, encoding="utf-8")
        exposed = Case(consumer.name, consumer.code, locations=(("iam", 6, 3),))
        with self.subTest(state="source-grant-no-longer-replaced"):
            self.assert_report(*self.execute(directory, cached=True), "json",
                               (exposed, source, override, changed))
        unknown = Case(settings.name, '''
            locals {
              override_sid = "Different"
              condition_values = var.environments
            }
        ''', True)
        settings_path.write_text(unknown.source, encoding="utf-8")
        with self.subTest(state="unknown-condition-does-not-reuse-complete-result"):
            self.assert_report(*self.execute(directory, cached=True), "json",
                               (consumer, source, override, unknown), partial=True)
        settings_path.write_text(settings.source, encoding="utf-8")
        with self.subTest(state="restricted-context-restored"):
            self.assert_report(*self.execute(directory, cached=True), "json",
                               (consumer, source, override, settings))

    def test_tfjson_public_formats_and_pure_json_autodetection(self):
        by_name = {case.name: case for case in JSON_CASES}
        cases = tuple(by_name[name] for name in (
            "tfjson_modern_public_ssh", "tfjson_public_bucket_acl",
            "tfjson_iam_generated_identity_policy", "tfjson_provider_tls_typed_interpolation",
            "tfjson_restricted_ingress"))
        directory = self.materialize(cases, "tfjson-formats")
        for mode in ("module-json", "module-sarif", "json", "sarif"):
            with self.subTest(mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, cases)

    def test_tfjson_public_direct_selection_extensions_and_staged_manifest(self):
        unsafe = next(case for case in JSON_CASES if case.name == "tfjson_modern_public_ssh")
        native = Case("native_selected", '''
            resource "aws_s3_bucket" "native_selected" {
              bucket = "native-selected-example"
              acl = "public-read" # expect:storage
            }
        ''')
        directory = self.materialize((unsafe, native), "tfjson-selection")
        for name in ("ignored.tf.json", "example.json", "values.tfvars.json"):
            (directory / name).write_text(unsafe.source, encoding="utf-8")
        terraform_cache = directory / ".terraform"
        terraform_cache.mkdir()
        (terraform_cache / "cached.tf.json").write_text(unsafe.source, encoding="utf-8")
        # Both runner and module include-ext add to default extensions. Use
        # explicit exclusions, direct paths or manifests to narrow selection.
        attempts = (
            ("mixed-directory", directory, "json", ("--exclude=ignored.tf.json",), (unsafe, native)),
            ("compound-runner", directory, "json", ("--include-ext=.tf.json", "--exclude=ignored.tf.json"), (unsafe, native)),
            ("compound-module", directory, "module-json", ("--include-ext=tf.json", "--exclude=ignored.tf.json"), (unsafe, native)),
            ("additive-native", directory, "json", ("--include-ext=tf", "--exclude=ignored.tf.json"), (unsafe, native)),
            ("native-only-exclusion", directory, "json", ("--exclude=*.tf.json",), (native,)),
            ("explicit-file", directory / unsafe.filename, "json", (), (unsafe,)),
        )
        for name, target, mode, options, cases in attempts:
            with self.subTest(selection=name):
                self.assert_report(*self.execute(target, mode, options), mode, cases)
        selected = self.artifact / "tfjson-selected.nul"
        selected.write_bytes(os.fsencode(directory / unsafe.filename) + b"\0" +
                             os.fsencode(directory / native.filename) + b"\0")
        with self.subTest(selection="module-manifest"):
            self.assert_report(*self.execute(directory, "module-json", ("--files-from=" + str(selected),)),
                               "module-json", (unsafe, native))
        commands = (["git", "init", "--initial-branch=main", str(directory)],
                    ["git", "-C", str(directory), "add", "--", unsafe.filename, native.filename])
        setup = []
        for command in commands:
            result = subprocess.run(command, text=True, capture_output=True, check=False)
            setup.append({"command": command, "exit": result.returncode,
                          "stdout": result.stdout, "stderr": result.stderr})
            self.assertEqual(result.returncode, 0, setup)
        (directory / "git-setup-receipt.json").write_text(json.dumps(setup, indent=2) + "\n", encoding="utf-8")
        with self.subTest(selection="staged-manifest"):
            self.assert_report(*self.execute(directory, extra=("--staged",)), "json", (unsafe, native))

    def test_tfjson_public_malformed_neighbor_keeps_native_finding(self):
        native = Case("native_neighbor", '''
            resource "aws_s3_bucket" "native_neighbor" {
              bucket = "native-neighbor-example"
              acl = "public-read" # expect:storage
            }
        ''')
        malformed = JSONCase("malformed_json", '{"resource": [true]}', True)
        directory = self.materialize((native, malformed), "tfjson-malformed-neighbor")
        for mode in ("module-json", "json", "sarif"):
            with self.subTest(mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, (native, malformed), partial=True)

    def test_tfjson_public_cache_tracks_cross_syntax_locals(self):
        consumer = Case("native_cache", '''
            resource "aws_iam_policy" "json_cache" {
              policy = jsonencode(local.permissions)
            }
        ''')
        settings = JSONCase("json_cache_settings", '''
            {"locals": {"permissions": {
              "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]
            }}}
        ''')
        directory = self.materialize((consumer, settings), "tfjson-context-cache")
        for attempt in range(2):
            with self.subTest(context="restricted-" + str(attempt)):
                self.assert_report(*self.execute(directory, cached=True), "json", (consumer, settings))
        path = directory / settings.filename
        changed = JSONCase(settings.name, settings.code.replace('"s3:GetObject"', '"*"'))
        path.write_text(changed.source, encoding="utf-8")
        exposed = Case(consumer.name, consumer.code, locations=(("iam", 2, 3),))
        with self.subTest(context="changed-to-wildcard"):
            self.assert_report(*self.execute(directory, cached=True), "json", (exposed, changed))
        unresolved = JSONCase(settings.name, settings.code.replace('"s3:GetObject"', '"${var.action}"'), True)
        path.write_text(unresolved.source, encoding="utf-8")
        with self.subTest(context="unresolved-input"):
            self.assert_report(*self.execute(directory, cached=True), "json", (consumer, unresolved), partial=True)
        path.write_text(settings.source, encoding="utf-8")
        with self.subTest(context="restricted-restored"):
            self.assert_report(*self.execute(directory, cached=True), "json", (consumer, settings))


if __name__ == "__main__":
    unittest.main()
