package ch.trancee.meshlink.detekt

import dev.detekt.api.Config
import dev.detekt.api.Entity
import dev.detekt.api.Finding
import dev.detekt.api.Rule
import org.jetbrains.kotlin.psi.KtArrayAccessExpression
import org.jetbrains.kotlin.psi.KtFile
import org.jetbrains.kotlin.psi.KtIfExpression
import org.jetbrains.kotlin.psi.KtNamedFunction
import org.jetbrains.kotlin.psi.KtReferenceExpression
import org.jetbrains.kotlin.psi.KtWhenExpression

/**
 * Constant-time discipline rule (ADR-0003, ticket 02).
 *
 * A parameter annotated `@Secret` introduces a secret. This rule flags any
 * data-dependent branch (`if` / `when`) whose condition touches a secret name,
 * or any array index `arr[idx]` whose index touches a secret name. Both leak
 * timing and are rejected at static-analysis time so primitives ship no
 * timing-conditional code.
 *
 * Detection is deliberately syntactic and file-scoped: secret parameter names
 * are collected from `@Secret`-annotated parameters, then any `if`/`when`/index
 * that references such a name is reported. This is intentional — a constant-time
 * linter must over-approximate (false positives are caught in review; false
 * negatives silently leak timing). The crypto package's small, `private`-heavy
 * footprint keeps false positives negligible.
 */
public class ConstantTimeRule(config: Config) :
  Rule(config, "do not branch on or index by @Secret values; use constant-time primitives") {

  private val secretNames = mutableSetOf<String>()

  override fun visitKtFile(file: KtFile) {
    secretNames.clear()
    super.visitKtFile(file)
  }

  override fun visitNamedFunction(function: KtNamedFunction) {
    function.valueParameters
      .asSequence()
      .filter { p -> p.annotationEntries.any { a -> a.text.contains("Secret") } }
      .mapNotNull { p -> p.name }
      .forEach { secretNames.add(it) }
    super.visitNamedFunction(function)
  }

  override fun visitIfExpression(expression: KtIfExpression) {
    val condition = expression.condition?.text
    if (condition != null && secretNames.any { condition.contains(it) }) {
      report(Finding(Entity.from(expression), "if branches on a @Secret value"))
    }
    super.visitIfExpression(expression)
  }

  override fun visitWhenExpression(expression: KtWhenExpression) {
    if (secretNames.any { n -> expression.text.contains(n) }) {
      report(Finding(Entity.from(expression), "when branches on a @Secret value"))
    }
    super.visitWhenExpression(expression)
  }

  override fun visitReferenceExpression(expression: KtReferenceExpression) {
    // `arr[idx]` parses as a KtArrayAccessExpression; the index ref (`idx`) is
    // parented by a KtContainerNode which is parented by the KtArrayAccessExpression.
    if (expression.text in secretNames && expression.parent?.parent is KtArrayAccessExpression) {
      report(Finding(Entity.from(expression), "array indexed by a @Secret value"))
    }
    super.visitReferenceExpression(expression)
  }
}
