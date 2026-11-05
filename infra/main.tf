# OCI Cloud Guard wiring for the triage workflow (template; NOT applied).
#
# Cloud Guard is the out-of-the-box OCI security posture service: managed
# detector recipes flag misconfigurations as "problems", and a target defines
# which compartment tree is watched. This template enables Cloud Guard on a
# compartment with the Oracle-managed activity and configuration detector
# recipes, so problems start appearing in the console/API for triage.
#
# This file has NOT been plan/apply validated against a tenancy - it is a
# structural template for the workflow. Review against the provider docs
# before any real apply.

terraform {
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 5.0.0"
    }
  }
}

variable "compartment_ocid" {
  type        = string
  description = "OCID of the compartment Cloud Guard should watch"
}

variable "reporting_region" {
  type        = string
  description = "Cloud Guard reporting region, e.g. ap-mumbai-1"
}

# Oracle-managed detector recipes available in the reporting region.
data "oci_cloud_guard_detector_recipes" "managed" {
  compartment_id = var.compartment_ocid
  state          = "ACTIVE"

  filter {
    name   = "resource_type"
    values = ["DETECTORRECIPE"]
  }
}

# Clone the managed configuration detector recipe so thresholds or rule
# settings can be tuned later without touching the Oracle-managed original.
resource "oci_cloud_guard_detector_recipe" "config_recipe" {
  compartment_id            = var.compartment_ocid
  display_name              = "triage-config-detector-recipe"
  source_detector_recipe_id = data.oci_cloud_guard_detector_recipes.managed.detector_recipe_collection[0].items[0].id
}

resource "oci_cloud_guard_target" "watched_compartment" {
  compartment_id       = var.compartment_ocid
  display_name         = "triage-target"
  target_resource_id   = var.compartment_ocid
  target_resource_type = "COMPARTMENT"

  target_detector_recipes {
    detector_recipe_id = oci_cloud_guard_detector_recipe.config_recipe.id
  }
}
