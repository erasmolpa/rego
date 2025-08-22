
package policy.github.release

# =============================================================================
# GITHUB RELEASE DEPLOYMENT POLICY
# =============================================================================
# This policy enforces security and compliance rules for GitHub release deployments
# across different environments (production, staging, development).
#
# The policy implements a comprehensive set of rules that ensure:
# - Controlled and tested deployments
# - Production environment isolation
# - Proper documentation and change tracking
# - Deployment window compliance
# - Required approvals and sign-offs
# - Change control after approval
# - Rollback procedures
# - Rate limiting and guardrails
# =============================================================================

default allow = false

# Convenient alias to environment rules from input
rules := data.policy.environments[input.env].rules

# =============================================================================
# POLICY AGGREGATOR
# =============================================================================
# Collects all violations from individual rules and determines final decision
# A deployment is allowed only if NO rules are violated
# =============================================================================

# Collect all violations from each rule category
deny[msg] if msg := controlled_tested_segregated_violations[_]
deny[msg] if msg := production_separation_violations[_]
deny[msg] if msg := documented_changes_violations[_]
deny[msg] if msg := deployment_windows_violations[_]
deny[msg] if msg := approvals_signoff_violations[_]
deny[msg] if msg := change_control_violations[_]
deny[msg] if msg := rollback_procedures_violations[_]
deny[msg] if msg := rate_limiting_guardrails[_]

# Final decision: allow only if no violations exist
allow if count(deny) == 0

# =============================================================================
# RULE 1: CONTROLLED, TESTED, AND SEGREGATED DEPLOYMENTS
# =============================================================================
# This rule ensures that deployments are properly controlled, tested, and
# deployed to the correct environments with appropriate restrictions.
#
# Key Requirements:
# - Tests must pass when required by environment
# - Artifacts must be signed when required
# - Release process must be controlled
# - Minimum number of approvers must be met
# - Only allowed branches can be deployed
# =============================================================================

# Violation: Tests are required but not passed
controlled_tested_segregated_violations[msg] if {
  rules.tests_passed
  not input.checks.tests
  msg := sprintf("CONTROLLED_TESTED_SEGREGATED_VIOLATION: Tests are required for %s environment but were not executed or did not pass. Ensure all required tests are run and pass before deployment.", [input.env])
}

# Violation: Artifact signature is required but not provided
controlled_tested_segregated_violations[msg] if {
  rules.artifact_signed
  not input.artifact_signed
  msg := sprintf("CONTROLLED_TESTED_SEGREGATED_VIOLATION: Artifact signature verification is required for %s environment but the artifact is not signed. Ensure all artifacts are properly signed before deployment.", [input.env])
}

# Violation: Release control is required but not enforced
controlled_tested_segregated_violations[msg] if {
  rules.release_controlled
  not input.release_controlled
  msg := sprintf("CONTROLLED_TESTED_SEGREGATED_VIOLATION: Release control is required for %s environment but the release is not controlled. Ensure proper release management processes are followed.", [input.env])
}

# Violation: Insufficient number of approvers
controlled_tested_segregated_violations[msg] if {
  rules.require_reviewers
  count(input.approvers) < rules.min_reviewers
  msg := sprintf("CONTROLLED_TESTED_SEGREGATED_VIOLATION: %s environment requires at least %d approvers, but only %d were provided. Ensure sufficient approvals are obtained before deployment.", [input.env, rules.min_reviewers, count(input.approvers)])
}

# Violation: Deployment to unauthorized branch
controlled_tested_segregated_violations[msg] if {
  rules.allowed_branches != null
  input.ref_type == "branch"
  not branch_allowed(rules.allowed_branches, input.ref)
  msg := sprintf("CONTROLLED_TESTED_SEGREGATED_VIOLATION: Branch %s is not authorized for %s environment. Only the following branches are allowed: %v", [input.ref, input.env, rules.allowed_branches])
}

# =============================================================================
# RULE 2: PRODUCTION ENVIRONMENT ISOLATION
# =============================================================================
# This rule ensures that production deployments are properly isolated
# from shared infrastructure to maintain security and stability.
#
# Key Requirements:
# - Production cannot run on shared infrastructure (unless explicitly allowed)
# - Dedicated runner groups may be required
# - Environment separation must be maintained
# =============================================================================

# Violation: Production deployment on shared infrastructure
production_separation_violations[msg] if {
  rules.shared_infra_except_core == false
  input.shared_infra == true
  msg := sprintf("PRODUCTION_ISOLATION_VIOLATION: %s environment cannot run on shared infrastructure. This environment requires dedicated, isolated infrastructure for security and compliance reasons.", [input.env])
}

# (if using runner groups, uncomment this and add rules.runner_group in policy.json)
# production_separation_violations[msg] if {
#   rules.runner_group != ""
#   input.runner_group != rules.runner_group
#   msg := sprintf("PRODUCTION_ISOLATION_VIOLATION: %s environment must use dedicated runner group '%s', but '%s' was specified. Ensure proper infrastructure isolation.", [input.env, rules.runner_group, input.runner_group])
# }

# =============================================================================
# RULE 3: DOCUMENTED CHANGES AND TICKET TRACKING
# =============================================================================
# This rule ensures that all changes are properly documented and tracked
# through appropriate ticketing systems for audit and compliance purposes.
#
# Key Requirements:
# - Changes must be recorded in change management system
# - Valid ticket IDs must be provided when required
# - Ticket format must match specified patterns
# =============================================================================

# Violation: Change not recorded in change management system
documented_changes_violations[msg] if {
  rules.change_recorded
  not input.change_recorded
  msg := sprintf("DOCUMENTATION_VIOLATION: Change must be recorded in the change management system for %s environment. This is required for audit trails and compliance purposes.", [input.env])
}

# Violation: Invalid or missing ticket ID
documented_changes_violations[msg] if {
  rules.require_ticket
  not valid_ticket(input.ticket_id, rules.ticket_pattern)
  msg := sprintf("DOCUMENTATION_VIOLATION: Valid ticket ID is required for %s environment deployment. Expected format: %s. Please provide a valid ticket ID before proceeding.", [input.env, rules.ticket_pattern])
}

# =============================================================================
# RULE 4: DEPLOYMENT WINDOWS AND TIMING CONTROLS
# =============================================================================
# This rule enforces deployment timing restrictions to ensure changes
# are deployed during approved windows and after required cooldown periods.
#
# Key Requirements:
# - Deployment dates must be pre-approved
# - Wait timers must be respected
# - Deployments must occur within approved time windows
# =============================================================================

# Violation: Deployment date not pre-approved
deployment_windows_violations[msg] if {
  rules.deployment_date_agreed
  not input.deployment_date_agreed
  msg := sprintf("TIMING_VIOLATION: Deployment date for %s environment has not been pre-approved. All production deployments must be scheduled and approved in advance.", [input.env])
}

# Violation: Wait timer not respected
deployment_windows_violations[msg] if {
  rules.wait_timer_seconds > 0
  input.wait_elapsed_seconds < rules.wait_timer_seconds
  msg := sprintf("TIMING_VIOLATION: Wait timer for %s environment has not elapsed. Required wait time: %d seconds, elapsed: %d seconds. Please wait for the full cooldown period before deployment.", [input.env, rules.wait_timer_seconds, input.wait_elapsed_seconds])
}

# Violation: Outside approved deployment windows
deployment_windows_violations[msg] if {
  rules.windows_utc != null
  not any_window_matches
  msg := sprintf("TIMING_VIOLATION: Current time is outside all approved deployment windows for %s environment. Approved windows: %v. Deployments are only allowed during these specified time periods.", [input.env, rules.windows_utc])
}

any_window_matches if {
  some w in rules.windows_utc
  in_window(input.now_utc, w)
}

# =============================================================================
# RULE 5: APPROVALS, SIGN-OFFS, AND EMERGENCY PROCEDURES
# =============================================================================
# This rule ensures proper approval workflows are followed and emergency
# procedures are properly configured and documented.
#
# Key Requirements:
# - Required sign-offs must be obtained before deployment
# - Emergency deployments must have retrospective sign-off enabled
# - Proper approval chains must be followed
# =============================================================================

# Violation: Missing required sign-off for non-emergency deployment
approvals_signoff_violations[msg] if {
  rules.signed_off
  not input.is_emergency
  not input.signed_off
  msg := sprintf("APPROVAL_VIOLATION: Required sign-off is missing for %s environment deployment. All non-emergency deployments must have proper approval before proceeding.", [input.env])
}

# Violation: Emergency deployment without retrospective sign-off
approvals_signoff_violations[msg] if {
  input.is_emergency
  rules.retrospective_signoff == false
  msg := sprintf("APPROVAL_VIOLATION: Emergency deployment to %s environment requires retrospective sign-off to be enabled. This ensures proper documentation and approval after emergency resolution.", [input.env])
}

# =============================================================================
# RULE 6: CHANGE CONTROL AFTER APPROVAL
# =============================================================================
# This rule prevents unauthorized changes after sign-off has been obtained,
# ensuring that what was approved is what gets deployed.
#
# Key Requirements:
# - Components must remain unchanged after sign-off
# - New sign-off required if changes are made after approval
# =============================================================================

# Violation: Components changed after sign-off
change_control_violations[msg] if {
  rules.components_unchanged
  input.components_changed_after_signoff
  msg := sprintf("CHANGE_CONTROL_VIOLATION: Components for %s environment deployment have been modified after sign-off was obtained. A new approval process is required before deployment can proceed.", [input.env])
}

# =============================================================================
# RULE 7: ROLLBACK PROCEDURES AND INSTRUCTIONS
# =============================================================================
# This rule ensures that proper rollback procedures are documented and
# available before any deployment to enable quick recovery if needed.
#
# Key Requirements:
# - Rollback instructions must be present when required
# - Recovery procedures must be documented
# =============================================================================

# Violation: Missing rollback instructions
rollback_procedures_violations[msg] if {
  rules.rollback_instructions_present
  not input.rollback_instructions_present
  msg := sprintf("ROLLBACK_VIOLATION: Rollback instructions are required for %s environment deployment but are not present. Rollback procedures must be documented before deployment to ensure operational readiness.", [input.env])
}

# =============================================================================
# RATE LIMITING AND GUARDRAILS
# =============================================================================
# This section implements protective measures to prevent deployment abuse
# and ensure system stability and operational excellence.
#
# Key Requirements:
# - Deployment frequency limits must be respected
# - System stability must be maintained
# - Operational excellence standards must be met
# =============================================================================

# Violation: Daily deployment limit exceeded
rate_limiting_guardrails[msg] if {
  rules.max_deployments_per_day > 0
  input.deployments_today > rules.max_deployments_per_day
  msg := sprintf("RATE_LIMIT_VIOLATION: Daily deployment limit for %s environment has been exceeded. Maximum allowed: %d, attempted: %d. This limit helps maintain system stability and operational excellence.", [input.env, rules.max_deployments_per_day, input.deployments_today])
}

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================
# These functions provide common validation logic used across multiple rules
# to ensure consistency and maintainability of the policy code.
# =============================================================================

# =============================================================================
# TICKET VALIDATION HELPER
# =============================================================================
# Validates ticket IDs against specified patterns for change tracking
#
# Parameters:
# - t: Ticket ID to validate
# - pat: Regex pattern to match against
#
# Returns: true if ticket is valid according to pattern
# =============================================================================

# Valid ticket if pattern is empty (no validation required)
valid_ticket(t, pat) if {
  t != ""
  pat == ""
}

# Valid ticket if it matches the specified regex pattern
valid_ticket(t, pat) if {
  t != ""
  regex.match(pat, t)
}

# =============================================================================
# BRANCH AUTHORIZATION HELPER
# =============================================================================
# Validates that deployment branch is in the allowed list
#
# Parameters:
# - allowed: List of allowed branch names
# - ref: Full git reference (e.g., "refs/heads/main")
#
# Returns: true if branch is authorized for deployment
# =============================================================================

branch_allowed(allowed, ref) if {
  some b in allowed
  ref == sprintf("refs/heads/%s", [b])
}

# =============================================================================
# TIME WINDOW VALIDATION HELPER
# =============================================================================
# Validates that current time falls within approved deployment windows
#
# Parameters:
# - ts: Timestamp to validate (RFC3339 format)
# - window: Time window in "HH:MM-HH:MM" format (UTC)
#
# Returns: true if timestamp is within the specified window
# =============================================================================

in_window(ts, window) if {
  parts := split(window, "-")
  start := parts[0]
  end := parts[1]
  
  # TODO: Implement proper time window validation
  # For now, we'll use a placeholder that always returns true
  # This should be replaced with actual time parsing and comparison logic
  # Example implementation:
  # hhmm := time.format("%H:%M", ts)
  # hhmm >= start
  # hhmm <= end
  
  true  # Placeholder - implement proper time window logic
}
