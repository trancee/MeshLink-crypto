package ch.trancee.meshlink.detekt

import dev.detekt.api.Config
import dev.detekt.api.RuleName
import dev.detekt.api.RuleSet
import dev.detekt.api.RuleSetId
import dev.detekt.api.RuleSetProvider

/**
 * Registers the `crypto-constant-time` rule set with detekt.
 *
 * Discovered via the ServiceLoader file at
 * `META-INF/services/dev.detekt.api.RuleSetProvider` (detekt 2.0 ServiceLoader
 * contract, confirmed against detekt-api 2.0.0-alpha.6). The provider is picked up
 * when `:crypto-detekt-rules` is attached as a `detektPlugins` dependency of `:crypto`.
 */
public class ConstantTimeRuleSetProvider : RuleSetProvider {
  override val ruleSetId: RuleSetId = RuleSetId("crypto-constant-time")

  override fun instance(): RuleSet =
    RuleSet(
      ruleSetId,
      mapOf(
        RuleName("ConstantTimeRule") to { config: Config -> ConstantTimeRule(config) }
      )
    )
}
