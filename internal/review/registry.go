package review

// DefaultRules returns the rules run by "review" and "audit". Every
// staged-diff rule that is advertised in the README must be listed here.
func DefaultRules(repositoryRoot string) []Rule {
	rules := []Rule{
		TodoRule{RepositoryRoot: repositoryRoot},
		DebugRule{RepositoryRoot: repositoryRoot},
		RiskRule{RepositoryRoot: repositoryRoot},
		PolicyRule{RepositoryRoot: repositoryRoot},
		SecurityRule{RepositoryRoot: repositoryRoot},
		ShellRule{RepositoryRoot: repositoryRoot},
		TLSRule{RepositoryRoot: repositoryRoot},
		PermissionsRule{RepositoryRoot: repositoryRoot},
		SlopRule{RepositoryRoot: repositoryRoot},
		SecretRule{RepositoryRoot: repositoryRoot},
		EntropyRule{RepositoryRoot: repositoryRoot},
		TraversalRule{RepositoryRoot: repositoryRoot},
		TaintRule{RepositoryRoot: repositoryRoot},
		ResolvedPathRule{RepositoryRoot: repositoryRoot},
		ClientTimeoutRule{RepositoryRoot: repositoryRoot},
		ScopeDefaultRule{RepositoryRoot: repositoryRoot},
		PluginTrustRule{RepositoryRoot: repositoryRoot},
		PrivilegedExecRule{RepositoryRoot: repositoryRoot},
		ProcessKillRule{RepositoryRoot: repositoryRoot},
		CredentialQueryRule{RepositoryRoot: repositoryRoot},
		CleartextTransportRule{RepositoryRoot: repositoryRoot},
		UnauthenticatedRouteRule{RepositoryRoot: repositoryRoot},
		CryptoRule{RepositoryRoot: repositoryRoot},
		DeserializationRule{RepositoryRoot: repositoryRoot},
		EvalRule{RepositoryRoot: repositoryRoot},
		XSSRule{RepositoryRoot: repositoryRoot},
		SQLiRule{RepositoryRoot: repositoryRoot},
		TouchTargetRule{RepositoryRoot: repositoryRoot},
		TestViewportChromeRule{RepositoryRoot: repositoryRoot},
		DesignSystemRule{RepositoryRoot: repositoryRoot},
		StaleStateRule{RepositoryRoot: repositoryRoot},
		ResourceLeakRule{RepositoryRoot: repositoryRoot},
		AsyncGapRule{RepositoryRoot: repositoryRoot},
		DeactivatedContextRule{RepositoryRoot: repositoryRoot},
		WatchOutsideBuildRule{RepositoryRoot: repositoryRoot},
		LifecycleSetStateRule{RepositoryRoot: repositoryRoot},
		HotPathRule{RepositoryRoot: repositoryRoot},
		AgentSpecRule{RepositoryRoot: repositoryRoot},
		FlutterSemanticsRule{RepositoryRoot: repositoryRoot},
		ScrollFocusRule{RepositoryRoot: repositoryRoot},
		A11yTestGapRule{RepositoryRoot: repositoryRoot},
		RustSafetyRule{RepositoryRoot: repositoryRoot},
		RustFFIPanicRule{RepositoryRoot: repositoryRoot},
		RustAsyncLockRule{RepositoryRoot: repositoryRoot},
		JVMCoroutineLeakRule{RepositoryRoot: repositoryRoot},
		JVMInsecureDeserializationRule{RepositoryRoot: repositoryRoot},
		CPPUnboundedBufferRule{RepositoryRoot: repositoryRoot},
		CSharpAsyncRule{RepositoryRoot: repositoryRoot},
	}
	return append(rules, ExtraRules(repositoryRoot)...)
}

// DefaultRulesWithOptions applies the degraded fallback to the rule set when
// the caller opted into degraded analysis.
func DefaultRulesWithOptions(repositoryRoot string, degraded bool) []Rule {
	rules := DefaultRules(repositoryRoot)
	if !degraded {
		return rules
	}
	for i, r := range rules {
		if slopRule, ok := r.(SlopRule); ok {
			slopRule.Degraded = true
			rules[i] = slopRule
		}
	}
	return rules
}
