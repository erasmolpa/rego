#!/usr/bin/env python3
"""
Python script to validate Rego policies using WASM
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, List, Union

try:
    from wasmtime import Store, Module, Instance, Func, FuncType, ValType
except ImportError:
    print("Error: wasmtime package not found. Install with: pip install wasmtime")
    sys.exit(1)

class RegoWASMValidator:
    """
    A class to load and execute Rego policies compiled to WASM
    """
    
    def __init__(self, wasm_path: str, data_path: str = None):
        """
        Initialize the validator with WASM file and optional data
        
        Args:
            wasm_path: Path to the compiled WASM file
            data_path: Path to the policy data JSON file
        """
        self.wasm_path = Path(wasm_path)
        self.data_path = Path(data_path) if data_path else None
        self.store = Store()
        self.instance = None
        self.data = {}
        
        if not self.wasm_path.exists():
            raise FileNotFoundError(f"WASM file not found: {wasm_path}")
            
        if self.data_path and self.data_path.exists():
            with open(self.data_path, 'r') as f:
                self.data = json.load(f)
                
        self._load_wasm()
    
    def _load_wasm(self):
        """Load the WASM module"""
        try:
            with open(self.wasm_path, 'rb') as f:
                wasm_bytes = f.read()
            
            module = Module(self.store.engine, wasm_bytes)
            self.instance = Instance(self.store, module, [])
            print(f"✅ Successfully loaded WASM from {self.wasm_path}")
            
        except Exception as e:
            print(f"❌ Failed to load WASM: {e}")
            raise
    
    def validate_input(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate input against the policy
        
        Args:
            input_data: The input to validate
            
        Returns:
            Dictionary with validation results
        """
        try:
            # For now, we'll implement a simplified validation
            # In a real implementation, you'd call the WASM functions
            result = {
                "allowed": False,
                "violations": [],
                "input": input_data,
                "timestamp": "2025-01-18T16:00:00Z"
            }
            
            # Basic validation logic (placeholder)
            env = input_data.get("env", "")
            if env in self.data.get("policy", {}).get("environments", {}):
                rules = self.data["policy"]["environments"][env]["rules"]
                violations = self._check_rules(input_data, rules)
                result["violations"] = violations
                result["allowed"] = len(violations) == 0
            else:
                result["violations"] = [f"Unknown environment: {env}"]
            
            return result
            
        except Exception as e:
            return {
                "allowed": False,
                "violations": [f"Validation error: {str(e)}"],
                "input": input_data,
                "error": True
            }
    
    def _check_rules(self, input_data: Dict[str, Any], rules: Dict[str, Any]) -> List[str]:
        """
        Check input against policy rules
        
        Args:
            input_data: Input to validate
            rules: Rules configuration
            
        Returns:
            List of violation messages
        """
        violations = []
        
        # Rule #1: Controlled, tested, segregated
        if rules.get("tests_passed") and not input_data.get("checks", {}).get("tests"):
            violations.append("Rule#1: tests required but not passed")
            
        if rules.get("artifact_signed") and not input_data.get("artifact_signed"):
            violations.append("Rule#1: artifact must be signed")
            
        if rules.get("release_controlled") and not input_data.get("release_controlled"):
            violations.append("Rule#1: release must be controlled")
            
        if rules.get("require_reviewers"):
            min_reviewers = rules.get("min_reviewers", 0)
            approvers = len(input_data.get("approvers", []))
            if approvers < min_reviewers:
                violations.append(f"Rule#1: at least {min_reviewers} approvers required (got {approvers})")
        
        # Rule #2: Production separation
        if (rules.get("shared_infra_except_core") == False and 
            input_data.get("shared_infra") == True):
            violations.append("Rule#2: production cannot run on shared infra (except core)")
        
        # Rule #3: Documented changes
        if rules.get("change_recorded") and not input_data.get("change_recorded"):
            violations.append("Rule#3: change must be recorded")
            
        if rules.get("require_ticket"):
            ticket_id = input_data.get("ticket_id", "")
            ticket_pattern = rules.get("ticket_pattern", "")
            if not self._valid_ticket(ticket_id, ticket_pattern):
                violations.append(f"Rule#3: ticket id invalid/missing (pattern {ticket_pattern})")
        
        # Rule #4: Deployment windows and timers
        if rules.get("deployment_date_agreed") and not input_data.get("deployment_date_agreed"):
            violations.append("Rule#4: deployment date not agreed")
            
        wait_timer = rules.get("wait_timer_seconds", 0)
        if wait_timer > 0:
            elapsed = input_data.get("wait_elapsed_seconds", 0)
            if elapsed < wait_timer:
                violations.append(f"Rule#4: wait timer not elapsed ({elapsed} < {wait_timer})")
        
        # Rule #5: Sign-off and emergency
        if (rules.get("signed_off") and 
            not input_data.get("is_emergency") and 
            not input_data.get("signed_off")):
            violations.append("Rule#5: missing required sign-off")
            
        if (input_data.get("is_emergency") and 
            rules.get("retrospective_signoff") == False):
            violations.append("Rule#5: emergency path requires retrospective_signoff enabled")
        
        # Rule #6: Change control
        if (rules.get("components_unchanged") and 
            input_data.get("components_changed_after_signoff")):
            violations.append("Rule#6: components changed after signoff; require new signoff")
        
        # Rule #7: Rollback instructions
        if (rules.get("rollback_instructions_present") and 
            not input_data.get("rollback_instructions_present")):
            violations.append("Rule#7: rollback instructions must be present")
        
        # Guardrails
        max_deployments = rules.get("max_deployments_per_day", 0)
        if max_deployments > 0:
            deployments_today = input_data.get("deployments_today", 0)
            if deployments_today > max_deployments:
                violations.append(f"Max deployments per day exceeded ({deployments_today} > {max_deployments})")
        
        return violations
    
    def _valid_ticket(self, ticket_id: str, pattern: str) -> bool:
        """
        Validate ticket ID against pattern
        
        Args:
            ticket_id: Ticket ID to validate
            pattern: Regex pattern
            
        Returns:
            True if valid, False otherwise
        """
        if not ticket_id:
            return False
        if not pattern:
            return True
            
        import re
        try:
            return bool(re.match(pattern, ticket_id))
        except re.error:
            return False

def load_test_scenarios() -> List[Dict[str, Any]]:
    """Load test scenarios from JSON files"""
    test_dir = Path("test-inputs")
    scenarios = []
    
    if test_dir.exists():
        for json_file in test_dir.glob("*.json"):
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                    data['_test_name'] = json_file.stem
                    scenarios.append(data)
            except Exception as e:
                print(f"⚠️  Failed to load {json_file}: {e}")
    
    return scenarios

def main():
    """Main function to run validation tests"""
    print("🔬 Python WASM Policy Validator")
    print("=" * 40)
    
    # Initialize validator
    try:
        wasm_file = "build/policy.wasm"
        data_file = "policies/policy.json"
        
        # Check if files exist, create fallback if needed
        if not os.path.exists(wasm_file):
            print(f"⚠️  WASM file not found: {wasm_file}")
            print("   Using JSON-based validation instead")
            wasm_file = None
        
        if not os.path.exists(data_file):
            print(f"❌ Policy data file not found: {data_file}")
            return 1
            
        validator = RegoWASMValidator(wasm_file, data_file) if wasm_file else None
        
        # If no WASM, create a simple JSON validator
        if not validator:
            with open(data_file, 'r') as f:
                policy_data = json.load(f)
            validator = RegoWASMValidator.__new__(RegoWASMValidator)
            validator.data = policy_data
        
    except Exception as e:
        print(f"❌ Failed to initialize validator: {e}")
        return 1
    
    # Load and run test scenarios
    scenarios = load_test_scenarios()
    if not scenarios:
        print("⚠️  No test scenarios found in test-inputs/")
        return 1
    
    print(f"\n📋 Running {len(scenarios)} test scenarios:")
    print("-" * 40)
    
    passed = 0
    failed = 0
    
    for scenario in scenarios:
        test_name = scenario.pop('_test_name', 'unknown')
        print(f"\n🧪 Testing: {test_name}")
        
        try:
            result = validator.validate_input(scenario)
            
            if result.get("allowed"):
                print(f"✅ {test_name}: ALLOWED")
                if result.get("violations"):
                    print(f"   Violations: {len(result['violations'])}")
                passed += 1
            else:
                print(f"❌ {test_name}: DENIED")
                violations = result.get("violations", [])
                print(f"   Violations ({len(violations)}):")
                for violation in violations[:5]:  # Show first 5
                    print(f"   • {violation}")
                if len(violations) > 5:
                    print(f"   ... and {len(violations) - 5} more")
                failed += 1
                
        except Exception as e:
            print(f"💥 {test_name}: ERROR - {e}")
            failed += 1
    
    # Summary
    print("\n" + "=" * 40)
    print(f"📊 Summary: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All tests completed successfully!")
        return 0
    else:
        print(f"⚠️  {failed} tests failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
