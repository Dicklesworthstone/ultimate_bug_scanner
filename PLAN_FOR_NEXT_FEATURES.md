# 🚀 UBS Advanced Features Roadmap: Leveraging ast-grep's Full Power

**Status:** Planning Phase
**Target:** UBS v5.0+
**Philosophy:** Go beyond pattern matching to *correlation analysis* and *contextual understanding*

---

## 📚 Table of Contents

1. [ast-grep Deep Dive: Understanding Our Foundation](#ast-grep-deep-dive)
2. [Feature #1: Resource Lifecycle Correlation](#feature-1-resource-lifecycle)
3. [Feature #2: Async Error Path Coverage](#feature-2-async-error-coverage)
4. [Feature #3: React Hooks Dependency Deep Analysis](#feature-3-react-hooks-analysis)
5. [Feature #4: Lightweight Taint Analysis](#feature-4-taint-analysis)
6. [Feature #5: Type Narrowing Validation](#feature-5-type-narrowing)
7. [Bonus Features: Research-Level Opportunities](#bonus-features)
8. [Implementation Roadmap](#implementation-roadmap)
9. [Technical Architecture](#technical-architecture)

---

## 🔬 ast-grep Deep Dive: Understanding Our Foundation

### **What Makes ast-grep Uniquely Powerful**

ast-grep is NOT just "grep for code" - it's a **structural pattern matcher** with deep semantic understanding.

#### **Core Capabilities We're Currently Using:**

```yaml
# Simple pattern matching (what we do now)
pattern: eval($ARG)
```

#### **Advanced Capabilities We're NOT Using Yet:**

1. **Relational Operators** - The game changer
2. **Compound Matchers** - Boolean logic over patterns
3. **Contextual Constraints** - Scope-aware matching
4. **Multi-pattern Rules** - Correlation across patterns
5. **Metavariable Reuse** - Track data flow
6. **Constraint System** - Type checking, regex on metavars

---

### **Deep Dive: Relational Operators (The Secret Weapon)**

This is where ast-grep becomes **revolutionary** for our use case:

#### **`inside` - Pattern A must be inside Pattern B**

```yaml
rule:
  pattern: $RESOURCE_ACQUIRE
  inside:
    pattern: |
      useEffect(() => {
        $$$BODY
      })
```

**What this does:**
- Finds resource acquisition (addEventListener, setInterval, etc.)
- BUT ONLY if it's inside a useEffect hook
- Enables scope-aware analysis

#### **`has` - Pattern A must contain Pattern B**

```yaml
rule:
  pattern: |
    useEffect(() => {
      $$$BODY
    }, $DEPS)
  has:
    pattern: window.addEventListener($EVENT, $HANDLER)
  # Now we can check if cleanup exists
```

**What this does:**
- Finds useEffect hooks
- That contain addEventListener
- Enables "this scope must have cleanup" validation

#### **`follows` / `precedes` - Ordering constraints**

```yaml
rule:
  pattern: const $VAR = await $PROMISE
  follows:
    pattern: if ($CONDITION) { $$$ }
  # await that follows a conditional
```

**What this does:**
- Temporal/spatial relationships
- "Cleanup must follow acquisition"
- "Error check must precede usage"

#### **`not` - Negative matching**

```yaml
rule:
  pattern: await $EXPR
  not:
    inside:
      pattern: |
        try {
          $$$BODY
        } catch {
          $$$HANDLER
        }
  # await NOT inside try/catch
```

**What this does:**
- Finds await that's NOT protected
- Enables "missing pattern" detection
- Critical for our use cases

---

### **Deep Dive: Metavariable Reuse (Data Flow Tracking)**

This is how we do **correlation analysis**:

```yaml
rules:
  - id: resource-leak
    pattern: window.addEventListener($EVENT, $HANDLER)
    # Captures $EVENT and $HANDLER as metavariables

  - id: cleanup-check
    pattern: window.removeEventListener($EVENT, $HANDLER)
    # Reuses SAME $EVENT and $HANDLER
    # ast-grep matches them structurally!
```

**The Magic:**
- ast-grep **unifies metavariables** across patterns
- If $EVENT is `'click'` in first pattern, it MUST be `'click'` in second
- This is **structural matching**, not string matching

**Example:**

```javascript
// Code:
window.addEventListener('resize', handleResize);
window.removeEventListener('click', handleClick); // Different handler!

// ast-grep correctly identifies: NO MATCH
// Because $HANDLER differs
```

This is **vastly more powerful** than regex-based matching.

---

### **Deep Dive: Constraint System**

We can add constraints to metavariables:

```yaml
rule:
  pattern: $OBJ.$PROP1.$PROP2.$PROP3
  constraints:
    PROP1:
      regex: "^[a-z]" # Must start lowercase
    PROP2:
      kind: member_expression # Must be property access, not method call
```

**Use cases:**
- Validate naming conventions
- Distinguish properties from methods
- Filter out false positives

---

### **Deep Dive: Multi-Pattern Analysis (The Killer Feature)**

ast-grep can match **multiple patterns simultaneously** and correlate them:

```yaml
rule:
  all:
    - pattern: const $VAR = $ACQUIRE
      inside:
        kind: function_declaration
    - not:
        pattern: $CLEANUP
        inside:
          same: function_declaration # Same function as above!
```

**This enables:**
- "Resource acquired in this function"
- "But no cleanup in same function"
- **Context-preserving correlation**

---

## 🎯 Feature #1: Resource Lifecycle Correlation Analysis

### **The Problem (Why LLMs Fail)**

LLMs generate code with resources but forget cleanup:

```javascript
function initDashboard() {
  // Acquisition
  window.addEventListener('resize', handleResize);
  const timer = setInterval(updateMetrics, 5000);
  const ws = new WebSocket('ws://api.example.com');

  // ❌ No cleanup anywhere!
  // Memory leak: all 3 resources live forever
}
```

**Traditional linters:** Miss this entirely (syntactically correct)
**TypeScript:** Can't detect (not a type error)
**ESLint:** Has react-hooks/exhaustive-deps but misses most cases

**UBS Lifecycle Analyzer:** Detects ALL unmatched resource acquisitions

---

### **Technical Design**

#### **Phase 1: Resource Pattern Catalog**

Define acquisition/cleanup pairs with ast-grep YAML rules:

```yaml
# rules/lifecycle/event-listener.yml
id: lifecycle.event-listener
language: javascript
severity: warning

acquisition:
  any:
    - pattern: window.addEventListener($EVENT, $HANDLER)
    - pattern: document.addEventListener($EVENT, $HANDLER)
    - pattern: $ELEM.addEventListener($EVENT, $HANDLER)

cleanup:
  any:
    - pattern: window.removeEventListener($EVENT, $HANDLER)
    - pattern: document.removeEventListener($EVENT, $HANDLER)
    - pattern: $ELEM.removeEventListener($EVENT, $HANDLER)

context:
  react_effect: |
    useEffect(() => {
      $$$BODY
      return () => { $$$CLEANUP }
    })

  class_destructor: |
    componentWillUnmount() {
      $$$CLEANUP
    }
```

**Other resource pairs:**

```yaml
# Timers
acquisition:
  - setInterval($FN, $DELAY)
  - setTimeout($FN, $DELAY)
cleanup:
  - clearInterval($TIMER)
  - clearTimeout($TIMER)

# WebSockets
acquisition:
  - new WebSocket($URL)
cleanup:
  - $WS.close()

# Fetch/AbortController
acquisition:
  - fetch($URL, { signal: $SIGNAL })
cleanup:
  - $CONTROLLER.abort()

# Event Emitters
acquisition:
  - $EMITTER.on($EVENT, $HANDLER)
  - $EMITTER.addListener($EVENT, $HANDLER)
cleanup:
  - $EMITTER.off($EVENT, $HANDLER)
  - $EMITTER.removeListener($EVENT, $HANDLER)

# Observers
acquisition:
  - new MutationObserver($CALLBACK)
  - new IntersectionObserver($CALLBACK)
  - new ResizeObserver($CALLBACK)
cleanup:
  - $OBSERVER.disconnect()

# Subscriptions (RxJS, etc.)
acquisition:
  - $OBSERVABLE.subscribe($HANDLER)
cleanup:
  - $SUBSCRIPTION.unsubscribe()
```

---

#### **Phase 2: Correlation Algorithm**

**The Challenge:** Match acquisitions to cleanups across scope boundaries

**Algorithm:**

```python
def analyze_lifecycle(file_path, language='javascript'):
    """
    Multi-pass analysis:
    1. Extract all acquisitions with context (scope, metavars)
    2. Extract all cleanups with context
    3. Match acquisitions to cleanups by metavariable unification
    4. Validate cleanup is in appropriate scope
    5. Report unmatched acquisitions
    """

    # Pass 1: Find acquisitions
    acquisitions = []
    for rule in ACQUISITION_RULES:
        matches = ast_grep.scan(file=file_path, rule=rule)
        for match in matches:
            acquisitions.append({
                'type': rule.resource_type,  # 'event-listener', 'timer', etc.
                'file': match.file,
                'line': match.line,
                'code': match.text,
                'scope': extract_scope(match),  # function/class/component
                'metavars': match.metavars,  # {EVENT: 'click', HANDLER: 'onClick'}
            })

    # Pass 2: Find cleanups
    cleanups = []
    for rule in CLEANUP_RULES:
        matches = ast_grep.scan(file=file_path, rule=rule)
        for match in matches:
            cleanups.append({
                'type': rule.resource_type,
                'scope': extract_scope(match),
                'metavars': match.metavars,
                'context': classify_cleanup_context(match),  # 'return', 'finally', 'unmount'
            })

    # Pass 3: Match acquisitions to cleanups
    leaks = []
    for acq in acquisitions:
        matched = False
        for cleanup in cleanups:
            if (acq['type'] == cleanup['type'] and
                metavars_match(acq['metavars'], cleanup['metavars']) and
                is_valid_cleanup_scope(acq['scope'], cleanup['scope'], cleanup['context'])):
                matched = True
                break

        if not matched:
            leaks.append(acq)

    return leaks
```

---

#### **Phase 3: Scope Validation (The Hard Part)**

**The Key Insight:** Not all cleanups are valid for all acquisitions.

**Valid cleanup contexts:**

```javascript
// 1. React useEffect return
useEffect(() => {
  window.addEventListener('resize', handleResize); // Acquisition
  return () => {
    window.removeEventListener('resize', handleResize); // ✅ Valid cleanup
  };
}, []);

// 2. Class componentWillUnmount
class Dashboard extends Component {
  componentDidMount() {
    window.addEventListener('resize', this.handleResize); // Acquisition
  }
  componentWillUnmount() {
    window.removeEventListener('resize', this.handleResize); // ✅ Valid cleanup
  }
}

// 3. Function with explicit cleanup return
function useWindowSize() {
  window.addEventListener('resize', handler); // Acquisition
  return () => window.removeEventListener('resize', handler); // ✅ Valid cleanup
}

// 4. Try/finally block
function process() {
  const timer = setInterval(poll, 1000); // Acquisition
  try {
    doWork();
  } finally {
    clearInterval(timer); // ✅ Valid cleanup
  }
}
```

**ast-grep rules for scope validation:**

```yaml
# Check if cleanup is in React effect return
rule:
  pattern: |
    useEffect(() => {
      $$$ACQUIRE
      return () => { $$$CLEANUP }
    })
  has:
    pattern: window.addEventListener($E, $H)
  has:
    pattern: window.removeEventListener($E, $H)
    inside:
      pattern: return () => { $$$ }
```

**Algorithm for scope validation:**

```python
def is_valid_cleanup_scope(acq_scope, cleanup_scope, cleanup_context):
    """
    Validate cleanup is in appropriate scope relative to acquisition.

    Rules:
    1. Same function + cleanup in return → Valid (custom hook)
    2. Same function + cleanup in finally → Valid
    3. Same class + cleanup in componentWillUnmount → Valid
    4. Same effect + cleanup in return function → Valid
    5. Cleanup in parent scope → Valid (if parent cleans up)
    6. Cleanup in sibling scope → Invalid (won't execute)
    7. Cleanup in child scope → Invalid (may not execute)
    """

    # Extract scope chain
    acq_chain = scope_chain(acq_scope)  # ['Dashboard', 'componentDidMount']
    cleanup_chain = scope_chain(cleanup_scope)  # ['Dashboard', 'componentWillUnmount']

    # Same immediate scope
    if acq_scope == cleanup_scope:
        # Check context
        if cleanup_context in ['return', 'finally', 'effect_cleanup']:
            return True
        return False  # Same scope but not in cleanup context

    # Cleanup in parent scope (common ancestor)
    common_ancestor = find_common_ancestor(acq_chain, cleanup_chain)
    if common_ancestor and is_lifecycle_method(cleanup_scope):
        # e.g., acquisition in componentDidMount, cleanup in componentWillUnmount
        return True

    # Cleanup in child scope → Invalid (won't always execute)
    if is_child_scope(cleanup_scope, acq_scope):
        return False

    # Cleanup in sibling scope → Invalid (won't execute)
    if is_sibling_scope(cleanup_scope, acq_scope):
        return False

    return False
```

---

#### **Phase 4: ast-grep Implementation**

**Step 1: Define YAML rules**

```yaml
# rules/lifecycle/event-listener-leak.yml
id: lifecycle.event-listener.leak
language: javascript
severity: warning
message: "Event listener added but never removed (memory leak)"

rule:
  # Find addEventListener in a scope
  pattern: $TARGET.addEventListener($EVENT, $HANDLER)

  # But NOT inside a useEffect with return cleanup
  not:
    inside:
      pattern: |
        useEffect(() => {
          $$$BODY
          return () => {
            $$$CLEANUP
          }
        })
      has:
        pattern: $TARGET.removeEventListener($EVENT, $HANDLER)
        inside:
          pattern: return () => { $$$ }

  # And NOT in a class with componentWillUnmount cleanup
  not:
    inside:
      kind: class_declaration
      has:
        pattern: |
          componentWillUnmount() {
            $$$CLEANUP
          }
        has:
          pattern: $TARGET.removeEventListener($EVENT, $HANDLER)
```

**Step 2: Bash integration**

```bash
analyze_resource_lifecycle() {
  local project_dir="$1"
  local output_json="$2"

  # Run ast-grep with lifecycle rules
  "${AST_GREP_CMD[@]}" scan \
    --rule rules/lifecycle/ \
    "$project_dir" \
    --json 2>/dev/null > "$output_json"

  # Post-process with Python for advanced correlation
  python3 - "$output_json" <<'PY'
import json, sys
from pathlib import Path

output_file = Path(sys.argv[1])
matches = json.loads(output_file.read_text())

# Group by resource type
leaks_by_type = {}
for match in matches:
    resource_type = match['ruleId'].split('.')[-1]
    leaks_by_type.setdefault(resource_type, []).append(match)

# Generate report
report = {
    'total_leaks': len(matches),
    'by_type': {
        resource_type: {
            'count': len(items),
            'samples': items[:3]  # Top 3 examples
        }
        for resource_type, items in leaks_by_type.items()
    }
}

print(json.dumps(report, indent=2))
PY
}
```

---

#### **Phase 5: Output Format**

```
▓▓▓ RESOURCE LIFECYCLE ANALYSIS
Detects: Unclosed resources, memory leaks, missing cleanup

  🔥 CRITICAL (12 found)
    Event listeners without cleanup
    Memory leak: resources accumulate on each render/mount

      src/Dashboard.tsx:45
        window.addEventListener('resize', handleResize)
        ❌ No matching removeEventListener in cleanup scope

        💡 Suggested fix:
        useEffect(() => {
          window.addEventListener('resize', handleResize);
          return () => window.removeEventListener('resize', handleResize);
        }, []);

  ⚠️  WARNING (8 found)
    Timers without clearInterval/clearTimeout

      src/Metrics.tsx:67
        setInterval(fetchMetrics, 5000)
        ❌ No clearInterval found

        💡 In React: store interval ID and clear in cleanup:
        useEffect(() => {
          const id = setInterval(fetchMetrics, 5000);
          return () => clearInterval(id);
        }, []);

  ⚠️  WARNING (3 found)
    WebSocket connections without .close()

      src/RealtimeData.tsx:23
        const ws = new WebSocket('ws://api.example.com')
        ❌ No ws.close() in cleanup

  📊 Lifecycle Analysis Summary:
    Total resources acquired: 45
    Properly cleaned up: 22 (49%)
    ❌ Memory leaks detected: 23 (51%)

    Breakdown:
      Event listeners: 12 leaks / 20 total (60% leak rate)
      Timers: 8 leaks / 15 total (53% leak rate)
      WebSockets: 3 leaks / 10 total (30% leak rate)
```

---

### **Value Proposition**

**Impact:**
- Catches **80%+ of memory leaks** in LLM-generated code
- Memory leaks cost **5-20 hours debugging** in production
- Explains **WHY** it's a leak (missing cleanup context)
- Suggests **HOW** to fix (shows proper pattern)

**Uniqueness:**
- **Nobody does comprehensive lifecycle analysis**
- ESLint react-hooks plugin only covers effects, misses classes/plain functions
- This works across React, Vue, vanilla JS, any framework

**Feasibility:** ⭐⭐⭐⭐⭐
- ast-grep's `inside`, `has`, `not` operators handle this perfectly
- ~1000-1500 lines of implementation (rules + correlation logic)
- Python post-processing for advanced matching

---

## 🎯 Feature #2: Async Error Path Coverage Analysis

### **The Problem**

LLMs generate async code but forget error handling:

```javascript
async function processOrder(orderId) {
  const order = await db.orders.findById(orderId);        // Can throw
  const payment = await stripe.charge(order.amount);      // Can throw
  const shipping = await shippo.createLabel(order);       // Can throw
  await email.send(order.customer, confirmation);         // Can throw
  return { success: true };
}

// ❌ 4 await points, ZERO error handlers
// If ANY step fails, entire app crashes with unhandled rejection
```

**Traditional linters:** Don't track coverage
**TypeScript:** Can't enforce try/catch
**UBS Async Analyzer:** Quantifies risk with **coverage metric**

---

### **Technical Design**

#### **Phase 1: Error Path Mapping**

**Identify all async operations:**

```yaml
# rules/async/await-points.yml
id: async.await-point
pattern: await $EXPR

# rules/async/promise-chains.yml
id: async.promise-chain
pattern: $PROMISE.then($HANDLER)

# rules/async/promise-calls.yml
id: async.promise-call
pattern: |
  const $VAR = $ASYNC_FN($$$ARGS)
constraints:
  ASYNC_FN:
    kind: call_expression
    # Functions known to return promises
```

---

#### **Phase 2: Error Handler Detection**

**Check for protection:**

```yaml
# Check if await is inside try/catch
rule:
  pattern: await $EXPR
  not:
    inside:
      pattern: |
        try {
          $$$BODY
        } catch ($ERROR) {
          $$$HANDLER
        }
```

**Check for .catch() handler:**

```yaml
rule:
  pattern: $PROMISE.then($SUCCESS)
  not:
    has:
      pattern: .catch($ERROR_HANDLER)
```

**Check for Promise.all error handling:**

```yaml
rule:
  pattern: await Promise.all($ARRAY)
  not:
    inside:
      pattern: try { $$$ } catch { $$$ }
```

---

#### **Phase 3: Coverage Calculation**

```python
def calculate_async_coverage(file_path):
    """
    Calculate error handling coverage for async code.

    Coverage = (handled_async_ops / total_async_ops) * 100
    """

    # Find all async operations
    awaits = ast_grep.scan(pattern='await $EXPR', file=file_path)
    promise_chains = ast_grep.scan(pattern='$P.then($H)', file=file_path)
    total_ops = len(awaits) + len(promise_chains)

    # Find protected operations
    protected = 0

    for await_match in awaits:
        # Check if inside try/catch
        if is_inside_try_catch(await_match):
            protected += 1
        # Check if function has .catch() at call site
        elif has_catch_at_call_site(await_match):
            protected += 1

    for promise_match in promise_chains:
        # Check if .catch() exists
        if has_catch_handler(promise_match):
            protected += 1
        # Check if await Promise.resolve().then() is in try/catch
        elif is_awaited_in_try(promise_match):
            protected += 1

    coverage = (protected / total_ops * 100) if total_ops > 0 else 100

    return {
        'total_async_ops': total_ops,
        'protected_ops': protected,
        'unprotected_ops': total_ops - protected,
        'coverage_percent': coverage,
        'unprotected_details': [...],
    }
```

---

#### **Phase 4: Call Graph Analysis (Advanced)**

**Track error propagation through functions:**

```javascript
// Function that can throw
async function fetchUser(id) {
  return await db.users.findById(id);  // Can throw
  // ❌ No try/catch, error propagates to caller
}

// Caller that doesn't handle
async function getProfile(id) {
  const user = await fetchUser(id);  // Can throw
  return user.profile;
  // ❌ No try/catch, error propagates further
}

// Top-level that finally handles
async function handler(req, res) {
  try {
    const profile = await getProfile(req.params.id);  // ✅ Protected here
    res.json(profile);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
}
```

**Algorithm:**

```python
def build_async_call_graph(project_dir):
    """
    Build call graph showing error propagation.

    For each async function:
    1. Find all async calls it makes
    2. Check if those calls are protected (try/catch)
    3. If not protected, mark function as "can throw"
    4. Trace up call chain to find where error is handled
    """

    # Extract all async functions
    async_functions = ast_grep.scan(
        pattern='async function $NAME($$$PARAMS) { $$$BODY }',
        file=project_dir
    )

    call_graph = {}

    for func in async_functions:
        func_name = func.metavars['NAME']

        # Find async calls within this function
        async_calls = extract_async_calls(func.metavars['BODY'])

        # Check which are protected
        unprotected = [
            call for call in async_calls
            if not is_protected(call)
        ]

        call_graph[func_name] = {
            'can_throw': len(unprotected) > 0,
            'unprotected_calls': unprotected,
            'callers': find_callers(func_name, project_dir),
        }

    # Propagate "can_throw" up the call chain
    propagate_errors(call_graph)

    return call_graph
```

---

#### **Phase 5: Output Format**

```
▓▓▓ ASYNC ERROR PATH COVERAGE
Detects: Unhandled promise rejections, missing try/catch, error propagation

  📊 Coverage Metrics:
    Total async operations: 47
    Protected: 23 (49%)
    ❌ Unprotected: 24 (51%)

    Coverage by file:
      src/api/orders.ts: 12% (1/8 protected) ⚠️ HIGH RISK
      src/services/payment.ts: 75% (9/12 protected) ✅ Good
      src/utils/fetch.ts: 0% (0/5 protected) 🔥 CRITICAL

  🔥 CRITICAL (24 unprotected async operations)

    src/api/orders.ts:processOrder:15
      await db.orders.findById(orderId)
      ❌ Not in try/catch
      ❌ No .catch() handler
      ❌ Function doesn't declare throws

      💡 Blast radius: If DB fails here, entire request crashes
      Suggested fix:
        try {
          const order = await db.orders.findById(orderId);
        } catch (error) {
          // Handle DB error (return 404, retry, log, etc.)
        }

    src/api/orders.ts:processOrder:18
      await stripe.charge(order.amount)
      ❌ Not in try/catch

      💡 Critical: Payment failure should be handled explicitly
      This is a financial operation - errors must be logged and reported

  ⚠️  WARNING: Error Propagation Chain Detected

    fetchUser (no try/catch)
      ↓ can throw
    getProfile (no try/catch)
      ↓ can throw
    renderProfilePage (no try/catch)
      ↓ can throw
    ✅ handler (protected with try/catch) - error stops here

    3 functions in chain can throw, protected only at top level
    💡 Consider protecting at fetchUser level for better error messages
```

---

### **Advanced: Suggest Error Handling Strategy**

Based on the type of async operation, suggest appropriate handling:

```python
def suggest_error_handling(async_operation):
    """
    Suggest appropriate error handling based on operation type.
    """

    # Database operations
    if is_database_call(async_operation):
        return {
            'strategy': 'try/catch with specific error types',
            'example': '''
                try {
                  const result = await db.query(...);
                } catch (error) {
                  if (error.code === 'NOT_FOUND') return null;
                  if (error.code === 'TIMEOUT') throw new ServiceUnavailable();
                  throw error; // Unexpected error
                }
            '''
        }

    # API calls
    if is_http_call(async_operation):
        return {
            'strategy': 'try/catch with retry logic',
            'example': '''
                try {
                  return await fetch(url);
                } catch (error) {
                  if (error.code === 'NETWORK_ERROR' && retries < 3) {
                    return retry(fetch, url);
                  }
                  throw new APIError('Failed to fetch', { cause: error });
                }
            '''
        }

    # File operations
    if is_file_operation(async_operation):
        return {
            'strategy': 'try/catch with fallback',
            'example': '''
                try {
                  return await fs.readFile(path);
                } catch (error) {
                  if (error.code === 'ENOENT') return DEFAULT_CONTENT;
                  throw error;
                }
            '''
        }

    # Payment/financial
    if is_payment_operation(async_operation):
        return {
            'strategy': 'try/catch with explicit logging and alerting',
            'example': '''
                try {
                  const result = await stripe.charge(amount);
                  await logPaymentSuccess(result);
                  return result;
                } catch (error) {
                  await logPaymentFailure(error);
                  await alertOps('Payment failed', error);
                  throw new PaymentError('Charge failed', { cause: error });
                }
            '''
        }
```

---

### **Value Proposition**

**Impact:**
- Silent failures are **THE WORST** bugs to debug
- Coverage metric quantifies risk (49% coverage = high risk)
- Explains **blast radius** (what breaks if this fails)
- Suggests **operation-specific** error handling

**Uniqueness:**
- **Coverage metric** - nobody does this
- **Call graph analysis** - trace errors through functions
- **Context-aware suggestions** - different strategies for DB vs API vs payments

**Feasibility:** ⭐⭐⭐⭐☆
- ast-grep handles pattern matching
- Call graph requires additional analysis (~800 lines)
- Python for coverage calculation and suggestions

---

## 🎯 Feature #3: React Hooks Dependency Deep Analysis

### **The Problem**

React's `useEffect`/`useCallback`/`useMemo` dependency arrays are **notoriously tricky**:

```javascript
function UserProfile({ userId }) {
  const [data, setData] = useState(null);
  const [theme, setTheme] = useState('light');

  // ❌ BUG 1: Missing dependency
  useEffect(() => {
    fetch(`/api/users/${userId}`)  // Uses userId
      .then(r => r.json())
      .then(setData);
  }, []); // Missing: userId - won't refetch on user change!

  // ❌ BUG 2: Stale closure
  const handleClick = useCallback(() => {
    console.log(`User ${userId} theme: ${theme}`);  // Uses userId, theme
  }, []); // Missing: userId, theme - always logs stale values!

  // ❌ BUG 3: Infinite loop
  const config = { userId, theme }; // New object every render
  useEffect(() => {
    applyConfig(config);
  }, [config]); // Object identity changes → infinite loop!
}
```

**ESLint react-hooks plugin:**
- Catches SOME cases
- Misses complex closures
- Doesn't explain CONSEQUENCES
- Doesn't detect infinite loops from object deps

**UBS Hooks Analyzer:**
- Catches ALL dependency issues
- Explains what will happen (stale data, infinite loops)
- Suggests fixes with context

---

### **Technical Design**

#### **Phase 1: Extract Hook Patterns**

```yaml
# Find useEffect with dependencies
id: hooks.use-effect
pattern: |
  useEffect(() => {
    $$$BODY
  }, $DEPS)

# Find useCallback
id: hooks.use-callback
pattern: |
  useCallback($CALLBACK, $DEPS)

# Find useMemo
id: hooks.use-memo
pattern: |
  useMemo(() => $VALUE, $DEPS)
```

---

#### **Phase 2: Closure Analysis**

**Extract all identifiers used in hook body:**

```python
def extract_identifiers(hook_body):
    """
    Find all identifiers referenced in hook body.

    Challenges:
    1. Distinguish local vars from external
    2. Ignore function declarations
    3. Track nested closures
    4. Handle destructuring
    """

    # Use ast-grep to find all identifiers
    identifiers = ast_grep.scan(
        pattern='$IDENTIFIER',
        text=hook_body,
        kind='identifier'
    )

    # Filter out:
    # 1. Locally declared variables (const, let, var inside hook)
    # 2. Function parameters
    # 3. Imports (not deps)
    external_refs = []
    local_declarations = extract_local_declarations(hook_body)

    for identifier in identifiers:
        name = identifier.text

        # Skip if locally declared
        if name in local_declarations:
            continue

        # Skip if it's a function/class declaration inside hook
        if is_local_function(identifier):
            continue

        # This is an external reference
        external_refs.append({
            'name': name,
            'line': identifier.line,
            'kind': classify_identifier(name),  # prop, state, ref, context, etc.
        })

    return external_refs
```

---

#### **Phase 3: Dependency Validation**

```python
def validate_dependencies(hook_match):
    """
    Check if all referenced identifiers are in deps array.
    """

    body = hook_match.metavars['BODY']
    deps_array = hook_match.metavars['DEPS']

    # Extract what's used
    used_identifiers = extract_identifiers(body)

    # Extract what's declared in deps
    declared_deps = parse_deps_array(deps_array)

    # Find missing
    missing = []
    for identifier in used_identifiers:
        # Special cases that don't need to be in deps
        if should_skip(identifier):
            # setState functions (stable)
            # Refs (stable)
            # Dispatch functions (stable)
            continue

        if identifier['name'] not in declared_deps:
            missing.append(identifier)

    # Find unnecessary (in deps but not used)
    unnecessary = []
    for dep in declared_deps:
        if dep not in [i['name'] for i in used_identifiers]:
            unnecessary.append(dep)

    return {
        'missing': missing,
        'unnecessary': unnecessary,
        'used_identifiers': used_identifiers,
        'declared_deps': declared_deps,
    }

def should_skip(identifier):
    """
    Identifiers that don't need to be in deps array.
    """
    name = identifier['name']
    kind = identifier['kind']

    # setState from useState (always stable)
    if kind == 'state_setter':
        return True

    # Refs from useRef (always stable)
    if kind == 'ref':
        return True

    # dispatch from useReducer (always stable)
    if name == 'dispatch' and kind == 'reducer_dispatch':
        return True

    # Stable imports
    if kind == 'import':
        return True

    return False
```

---

#### **Phase 4: Infinite Loop Detection**

```python
def detect_infinite_loops(hook_match):
    """
    Detect dependencies that change every render (infinite loops).

    Common culprits:
    1. Object/array literals in deps: [{ userId }]
    2. Inline arrow functions: [() => foo()]
    3. Object created in component body: [config]
    """

    deps_array = hook_match.metavars['DEPS']
    deps = parse_deps_array(deps_array)

    risky_deps = []

    for dep in deps:
        # Check if dep is object literal
        if is_object_literal(dep):
            risky_deps.append({
                'name': dep,
                'reason': 'Object literal in deps - new object every render',
                'fix': 'Use useMemo to memoize object',
                'severity': 'critical',
            })

        # Check if dep is array literal
        if is_array_literal(dep):
            risky_deps.append({
                'name': dep,
                'reason': 'Array literal in deps - new array every render',
                'fix': 'Use useMemo to memoize array',
                'severity': 'critical',
            })

        # Check if dep is inline function
        if is_inline_function(dep):
            risky_deps.append({
                'name': dep,
                'reason': 'Inline function in deps - new function every render',
                'fix': 'Use useCallback to memoize function',
                'severity': 'critical',
            })

        # Check if dep is object created in render
        if is_unstable_object(dep, hook_match.scope):
            risky_deps.append({
                'name': dep,
                'reason': f'{dep} is created in render without memoization',
                'fix': f'Wrap {dep} in useMemo',
                'severity': 'warning',
            })

    return risky_deps
```

---

#### **Phase 5: Consequence Explanation**

This is what makes our analyzer **revolutionary** - we explain WHAT WILL HAPPEN:

```python
def explain_consequences(validation_result):
    """
    Explain real-world consequences of dependency issues.
    """

    consequences = []

    # Missing dependencies
    for missing in validation_result['missing']:
        if missing['kind'] == 'prop':
            consequences.append({
                'type': 'stale_data',
                'severity': 'critical',
                'explanation': f'''
                    When {missing['name']} changes, effect won't re-run.
                    Result: UI shows stale data from previous {missing['name']}.
                    Example: User changes but profile still shows old user.
                ''',
            })

        elif missing['kind'] == 'state':
            consequences.append({
                'type': 'stale_closure',
                'severity': 'warning',
                'explanation': f'''
                    Callback captures stale {missing['name']}.
                    Result: Always uses initial value, even after state updates.
                    Example: Click always logs initial state, not current.
                ''',
            })

    # Infinite loops
    for risky in validation_result.get('infinite_loops', []):
        consequences.append({
            'type': 'infinite_loop',
            'severity': 'critical',
            'explanation': f'''
                {risky['name']} changes every render.
                Result: Effect runs → triggers render → effect runs → infinite loop.
                Impact: Browser freezes, app crashes, API spammed with requests.
            ''',
        })

    return consequences
```

---

#### **Phase 6: ast-grep Implementation**

```yaml
# rules/react/use-effect-missing-deps.yml
id: react.use-effect.missing-deps
language: typescript
severity: error
message: "useEffect has missing dependencies"

rule:
  pattern: |
    useEffect(() => {
      $$$BODY
    }, $DEPS)

# This is where we'd need custom analysis
# ast-grep can extract the pattern, but we need Python
# to do the closure analysis and dep validation

# We can at least catch obvious cases:
```

```yaml
# Catch empty deps with obvious external refs
id: react.use-effect.empty-deps-with-usage
severity: error
message: "useEffect uses external values but has empty deps"

rule:
  pattern: |
    useEffect(() => {
      $$$BODY
    }, [])

  has:
    any:
      # Uses props
      - pattern: props.$PROP
      # Uses state from component
      - pattern: $IDENTIFIER
        constraints:
          IDENTIFIER:
            # This is tricky - need to determine if it's external
            # Might need Python post-processing
```

**Better approach: Use ast-grep for extraction, Python for validation**

```bash
analyze_react_hooks() {
  local project_dir="$1"

  # Extract all hooks with ast-grep
  "${AST_GREP_CMD[@]}" scan \
    --pattern 'useEffect(() => { $$$BODY }, $DEPS)' \
    --json \
    "$project_dir" > /tmp/hooks.json

  # Analyze with Python
  python3 - /tmp/hooks.json <<'PY'
import json, sys
from pathlib import Path

hooks = json.load(Path(sys.argv[1]).open())

for hook in hooks:
    body = hook['metavars']['BODY']
    deps = hook['metavars']['DEPS']

    # Extract identifiers from body
    identifiers = extract_identifiers(body)

    # Parse deps array
    declared_deps = parse_deps_array(deps)

    # Validate
    missing = [i for i in identifiers if i not in declared_deps and not should_skip(i)]

    if missing:
        print(f"Missing deps in {hook['file']}:{hook['line']}: {missing}")
        explain_consequence(missing, hook)
PY
}
```

---

### **Output Format**

```
▓▓▓ REACT HOOKS DEPENDENCY ANALYSIS
Detects: Missing dependencies, stale closures, infinite loops

  🔥 CRITICAL (8 found)
    Missing dependencies causing stale data

    src/UserProfile.tsx:15
      useEffect(() => {
        fetch(`/api/users/${userId}`)  // Uses: userId
        .then(setData);
      }, []);  // Missing: userId

      ⚠️ CONSEQUENCE: Stale data bug
      When userId changes (route param, prop update), effect won't re-run.
      Result: Shows profile for OLD user, not new user.

      Bug scenario:
        1. User views profile for userId=123
        2. User navigates to userId=456
        3. Effect doesn't re-run (userId not in deps)
        4. UI still shows data for user 123

      💡 Fix: useEffect(() => {...}, [userId])

  🔥 CRITICAL (3 found)
    Infinite loop risk - object deps without memoization

    src/Dashboard.tsx:42
      const config = { userId, theme };  // New object every render
      useEffect(() => {
        applyConfig(config);
      }, [config]);  // Object identity changes every render!

      ⚠️ CONSEQUENCE: Infinite loop
      Flow:
        1. Component renders → creates new config object
        2. config identity changed → effect triggers
        3. Effect calls applyConfig → may trigger state update
        4. State update → component re-renders → goto 1

      Result: Browser freezes, infinite API calls, app crashes

      💡 Fix:
      const config = useMemo(() => ({ userId, theme }), [userId, theme]);
      useEffect(() => {...}, [config]);

  ⚠️  WARNING (12 found)
    Stale closures in callbacks

    src/UserProfile.tsx:28
      const handleClick = useCallback(() => {
        console.log(`User: ${userId}, Theme: ${theme}`);
      }, []);  // Missing: userId, theme

      ⚠️ CONSEQUENCE: Stale closure
      Callback captures initial values of userId, theme.
      Even after they update, callback always logs original values.

      Example:
        Initial: userId=1, theme='light'
        Click → logs "User: 1, Theme: light" ✅

        Update: userId=2, theme='dark'
        Click → logs "User: 1, Theme: light" ❌ WRONG!

      💡 Fix: useCallback(() => {...}, [userId, theme])

  📊 Hooks Analysis Summary:
    Total hooks analyzed: 45
    useEffect: 28
    useCallback: 12
    useMemo: 5

    Issues found: 23 (51% have issues!)
    Critical (missing deps): 8
    Critical (infinite loops): 3
    Warnings (stale closures): 12
```

---

### **Value Proposition**

**Impact:**
- React hooks bugs are **extremely common** in LLM code
- Stale closures cause subtle, confusing bugs
- Infinite loops crash browsers
- **Explains consequences** - this is unique

**Uniqueness:**
- ESLint plugin exists but doesn't explain consequences
- Infinite loop detection is missing from ESLint
- Consequence explanation is revolutionary

**Feasibility:** ⭐⭐⭐⭐☆
- ast-grep extracts patterns
- Python does closure analysis (~600 lines)
- Consequence templates (~200 lines)

---

## 🎯 Feature #4: Lightweight Taint Analysis

### **The Problem**

User input flows to dangerous sinks without sanitization:

```javascript
// LLM generates:
app.post('/comment', (req, res) => {
  const comment = req.body.text;  // ← TAINT SOURCE (user input)

  // Flows through variables
  const html = `<div>${comment}</div>`;

  // Reaches dangerous sink
  response.send(html);  // ← XSS! Unsanitized user input in HTML
});
```

**Traditional:** Pattern matching catches `innerHTML` but misses dataflow
**UBS Taint Analysis:** Tracks data from source → sink

---

### **Technical Design**

#### **Phase 1: Mark Taint Sources**

```yaml
# User input sources
taint_sources:
  - pattern: req.body.$FIELD
  - pattern: req.query.$FIELD
  - pattern: req.params.$FIELD
  - pattern: event.target.value
  - pattern: window.location.$PROP
  - pattern: localStorage.getItem($KEY)
  - pattern: $FORM.get($NAME)  # FormData
```

#### **Phase 2: Track Data Flow**

```python
def track_taint_flow(source_match, file_ast):
    """
    Track how tainted data flows through code.

    Flows through:
    1. Variable assignments: const x = tainted
    2. String concatenation: `<div>${tainted}</div>`
    3. Function calls: sanitize(tainted)
    4. Return values: return tainted
    5. Object properties: obj.field = tainted
    """

    tainted_var = source_match.metavars.get('FIELD') or 'unknown'
    flows = []

    # Find assignments
    assignments = ast_grep.scan(
        pattern=f'const $VAR = $EXPR',
        # Where $EXPR contains tainted_var
    )

    # Track through each assignment
    for assign in assignments:
        if contains_identifier(assign.metavars['EXPR'], tainted_var):
            new_var = assign.metavars['VAR']
            flows.append({
                'type': 'assignment',
                'from': tainted_var,
                'to': new_var,
                'line': assign.line,
            })

            # Recursively track new_var
            flows.extend(track_taint_flow_from(new_var, file_ast))

    return flows
```

#### **Phase 3: Detect Dangerous Sinks**

```yaml
dangerous_sinks:
  # XSS sinks
  - pattern: $ELEM.innerHTML = $VALUE
    vulnerability: XSS
    sanitizer_required: DOMPurify.sanitize

  - pattern: document.write($VALUE)
    vulnerability: XSS

  - pattern: eval($VALUE)
    vulnerability: Code injection

  # SQL injection
  - pattern: db.query($SQL)
    vulnerability: SQL injection
    sanitizer_required: parameterized query

  # Command injection
  - pattern: exec($CMD)
    vulnerability: Command injection
```

#### **Phase 4: Find Sanitizers**

```yaml
sanitizers:
  - pattern: DOMPurify.sanitize($TAINTED)
    removes_taint: true
    protects_against: [XSS]

  - pattern: escapeHtml($TAINTED)
    removes_taint: true
    protects_against: [XSS]

  - pattern: $DB.query($SQL, $PARAMS)
    # Parameterized query
    removes_taint: true
    protects_against: [SQL injection]
```

---

### **Implementation Sketch**

```python
def analyze_taint(file_path):
    """
    Lightweight taint analysis.

    Steps:
    1. Find all taint sources
    2. For each source, track data flow
    3. Check if flow reaches dangerous sink
    4. Check if sanitizer exists in path
    5. Report unsanitized paths
    """

    vulnerabilities = []

    # Find sources
    sources = find_taint_sources(file_path)

    for source in sources:
        # Track how data flows
        flow_paths = track_taint_flow(source, file_path)

        # Check each path for dangerous sinks
        for path in flow_paths:
            sink = path.get('sink')
            if sink and is_dangerous_sink(sink):
                # Check if sanitized
                has_sanitizer = any(
                    is_sanitizer(node) for node in path['nodes']
                )

                if not has_sanitizer:
                    vulnerabilities.append({
                        'type': sink['vulnerability'],
                        'source': source,
                        'sink': sink,
                        'path': path,
                        'severity': 'critical',
                    })

    return vulnerabilities
```

---

### **Value Proposition**

**Impact:**
- XSS and SQL injection are **top security vulnerabilities**
- Catches vulnerabilities that pattern matching misses
- Explains full attack path (source → sink)

**Uniqueness:**
- Lightweight flow analysis (not full taint system)
- Focused on most common vulnerabilities
- Explains attack scenario

**Feasibility:** ⭐⭐⭐☆☆
- More complex than previous features
- Need dataflow analysis (~1000 lines)
- But doable with ast-grep + Python

---

## 🎯 Feature #5: Type Narrowing Validation

### **The Problem**

TypeScript allows structurally sound but behaviorally wrong code:

```typescript
function processValue(x: string | number) {
  if (typeof x === 'string') {
    console.log(x.toUpperCase());  // ✅ OK, x is string here
  }

  // Later, outside the if block:
  return x.toUpperCase();  // ❌ TypeScript allows this!
  // But at runtime: crashes if x is number
}
```

**TypeScript:** ✅ No error (structurally sound)
**Runtime:** 💥 Crash if x is number
**UBS:** Detects behavioral assumption outside narrow scope

---

### **Technical Design**

#### **Phase 1: Find Type Guards**

```yaml
type_guards:
  - pattern: typeof $VAR === $TYPE
  - pattern: $VAR instanceof $CLASS
  - pattern: Array.isArray($VAR)
  - pattern: $VAR?.hasOwnProperty($PROP)
```

#### **Phase 2: Track Narrowing Scope**

```python
def track_type_narrowing(guard_match):
    """
    Determine where type is narrowed.

    After:
      if (typeof x === 'string') { ... }

    Inside if block: x is string
    Outside if block: x returns to string | number
    """

    var_name = guard_match.metavars['VAR']
    narrow_type = guard_match.metavars['TYPE']

    # Find the if block
    if_block = find_parent_if_statement(guard_match)

    narrow_scope = {
        'variable': var_name,
        'narrowed_to': narrow_type,
        'scope_start': if_block.start_line,
        'scope_end': if_block.end_line,
    }

    return narrow_scope
```

#### **Phase 3: Validate Type Assumptions**

```python
def validate_type_assumptions(file_path):
    """
    Find type assumptions (method calls, property access)
    and validate they're in narrow scope.
    """

    issues = []

    # Find all type guards
    guards = find_type_guards(file_path)

    # For each guard, track narrow scope
    for guard in guards:
        narrow_scope = track_type_narrowing(guard)
        var = narrow_scope['variable']

        # Find usages that assume narrow type
        assumptions = find_type_assumptions(var, file_path)

        for assumption in assumptions:
            # Check if usage is inside narrow scope
            if not is_inside_scope(assumption, narrow_scope):
                issues.append({
                    'variable': var,
                    'narrowed_to': narrow_scope['narrowed_to'],
                    'narrow_scope': narrow_scope,
                    'assumption': assumption,
                    'line': assumption.line,
                })

    return issues
```

---

### **Value Proposition**

**Impact:**
- Catches TypeScript blind spots
- Behavioral validation vs structural validation
- Prevents runtime crashes in typed code

**Feasibility:** ⭐⭐⭐⭐☆
- ast-grep for pattern extraction
- Control flow analysis for scope tracking
- ~500 lines implementation

---

## 🔬 Bonus Features: Research-Level Opportunities

### **6. Side Effect Purity Analysis**

Detect functions claiming to be pure but with hidden side effects:

```javascript
// Claims to be pure (calculate)
function calculateTotal(items) {
  let total = 0;
  items.forEach(item => {
    total += item.price;
    item.processed = true;  // ❌ SIDE EFFECT! Mutates input
  });
  return total;
}
```

**Detect:**
- Parameter mutations
- Global state access
- I/O operations
- Non-determinism (Date.now(), Math.random())

---

### **7. Race Condition Detection**

Find TOCTOU (time-of-check-time-of-use) bugs:

```javascript
// Check
if (await fs.exists(filePath)) {
  // Use (but file might be deleted between check and use!)
  const data = await fs.readFile(filePath);
}
```

**Detect:**
- Async checks followed by async uses
- Shared state accessed without locks
- Event handler race conditions

---

### **8. Timing Attack Vulnerability**

Find timing-sensitive comparisons:

```javascript
// ❌ Vulnerable to timing attacks
function checkPassword(input, stored) {
  return input === stored;  // String comparison stops early
}

// ✅ Safe (constant time)
function safeCheck(input, stored) {
  return crypto.timingSafeEqual(input, stored);
}
```

---

## 🗺️ Implementation Roadmap

### **Phase 1: Foundation (v5.0)**

**Timeline:** 4-6 weeks

1. **Week 1-2:** Deep ast-grep integration
   - Advanced rule system
   - Metavariable correlation
   - Multi-pattern matching

2. **Week 3-4:** Resource Lifecycle Analysis (Feature #1)
   - Event listeners
   - Timers
   - WebSockets
   - Basic scope validation

3. **Week 5-6:** Testing and refinement
   - Test suite with 100+ cases
   - False positive reduction
   - Documentation

**Deliverable:** UBS v5.0 with Resource Lifecycle Analysis

---

### **Phase 2: Async & Hooks (v5.1)**

**Timeline:** 4-6 weeks

1. **Week 1-2:** Async Error Coverage (Feature #2)
   - await/Promise detection
   - try/catch validation
   - Coverage metrics

2. **Week 3-4:** React Hooks Analysis (Feature #3)
   - Dependency extraction
   - Closure analysis
   - Consequence explanation

3. **Week 5-6:** Integration and polish

**Deliverable:** UBS v5.1 with Async + Hooks analysis

---

### **Phase 3: Security (v6.0)**

**Timeline:** 6-8 weeks

1. **Week 1-3:** Lightweight Taint Analysis (Feature #4)
   - Source/sink detection
   - Basic dataflow
   - Sanitizer validation

2. **Week 4-5:** Type Narrowing (Feature #5)
   - Type guard detection
   - Scope tracking
   - Assumption validation

3. **Week 6-8:** Security hardening
   - Timing attacks
   - Race conditions
   - Comprehensive security suite

**Deliverable:** UBS v6.0 with Security Focus

---

## 🏗️ Technical Architecture

### **Module Structure**

```
modules/
├── ubs-js.sh                    # Main JS/TS scanner
├── ubs-js-lifecycle.sh          # Resource lifecycle analysis
├── ubs-js-async.sh              # Async error coverage
├── ubs-js-react-hooks.sh        # React hooks analysis
├── ubs-js-taint.sh              # Taint analysis
└── ubs-js-types.sh              # Type narrowing

rules/
├── lifecycle/
│   ├── event-listeners.yml
│   ├── timers.yml
│   ├── websockets.yml
│   └── observers.yml
├── async/
│   ├── await-coverage.yml
│   ├── promise-chains.yml
│   └── error-handlers.yml
├── react/
│   ├── use-effect-deps.yml
│   ├── use-callback-deps.yml
│   └── infinite-loops.yml
├── taint/
│   ├── sources.yml
│   ├── sinks.yml
│   └── sanitizers.yml
└── types/
    └── narrowing.yml

helpers/
├── correlation.py               # Metavariable matching
├── dataflow.py                  # Taint flow tracking
├── scope.py                     # Scope analysis
└── explain.py                   # Consequence explanations
```

---

### **Data Flow**

```
┌─────────────────────────────────────────┐
│  UBS Main Runner (Bash)                 │
│  - Detects languages                    │
│  - Invokes module scanners              │
└─────────────┬───────────────────────────┘
              │
              ↓
┌─────────────────────────────────────────┐
│  Module Scanner (ubs-js.sh)             │
│  - Runs ast-grep with YAML rules        │
│  - Extracts matches to JSON              │
└─────────────┬───────────────────────────┘
              │
              ↓
┌─────────────────────────────────────────┐
│  Specialized Analyzers (Bash)           │
│  - ubs-js-lifecycle.sh                  │
│  - ubs-js-async.sh                      │
│  - ubs-js-react-hooks.sh                │
└─────────────┬───────────────────────────┘
              │
              ↓
┌─────────────────────────────────────────┐
│  Python Post-Processors                  │
│  - Correlation logic                     │
│  - Dataflow analysis                     │
│  - Consequence explanation               │
└─────────────┬───────────────────────────┘
              │
              ↓
┌─────────────────────────────────────────┐
│  Unified JSON Output                     │
│  - Findings with context                 │
│  - Consequences explained                │
│  - Suggested fixes                       │
└─────────────────────────────────────────┘
```

---

## 📊 Success Metrics

### **Feature #1: Resource Lifecycle**

**Targets:**
- Detect 90%+ of event listener leaks
- Detect 90%+ of timer leaks
- False positive rate <15%
- Detection time <2s per 10K lines

**Validation:**
- Run on top 100 React repos
- Manually verify findings
- Compare against manual review

---

### **Feature #2: Async Error Coverage**

**Targets:**
- Calculate coverage for 95%+ of async code
- Detect all unprotected await
- Suggest context-appropriate handlers
- Coverage calculation <1s per file

**Validation:**
- Run on production codebases
- Compare coverage before/after fixes
- Verify crash rate reduction

---

### **Feature #3: React Hooks**

**Targets:**
- Detect 95%+ of missing deps
- Detect 100% of infinite loop patterns
- Explain consequences for every finding
- <3s analysis time for typical component

**Validation:**
- Test against React codebase
- Compare with ESLint plugin
- Measure unique findings

---

## 🎯 Competitive Moat

### **What Makes These Features Unique**

1. **Correlation Analysis** - Not just pattern matching
2. **Consequence Explanation** - Not just "this is wrong"
3. **Context Awareness** - Understands scope, lifecycle, flow
4. **LLM-First Design** - Optimized for AI-generated code
5. **Multi-Language** - Same analysis across 7 languages

**Nobody else does this combination:**
- ESLint: Pattern matching, no correlation
- Semgrep: Pattern matching, no consequence explanation
- SonarQube: Comprehensive but slow, human-first
- DeepCode: ML-based but cloud-only, no explanation

**UBS becomes:** The fast, local, explainable, correlation-aware bug oracle for LLM code.

---

## 🚀 Getting Started

### **Priority Order**

1. **Resource Lifecycle** - Highest impact, most feasible
2. **Async Error Coverage** - High impact, unique metric
3. **React Hooks** - Large user base, clear value
4. **Taint Analysis** - Security critical
5. **Type Narrowing** - TypeScript blind spot

### **First Implementation: Resource Lifecycle**

**Next Steps:**
1. Create `rules/lifecycle/` directory with YAML rules
2. Implement `ubs-js-lifecycle.sh` module
3. Build Python correlation logic in `helpers/correlation.py`
4. Test on 10 React projects
5. Iterate on false positives
6. Document and release

**Estimated Effort:** 1-2 weeks for MVP, 4 weeks for production-ready

---

## 💡 Innovation Principles

### **What Makes Analysis "Revolutionary"**

1. **Correlation > Patterns**
   - Bad: "This pattern is dangerous"
   - Good: "This pattern HERE has no matching cleanup THERE"

2. **Consequences > Rules**
   - Bad: "Missing dependency"
   - Good: "Missing dependency → stale data → shows wrong user profile"

3. **Context > Syntax**
   - Bad: "addEventListener detected"
   - Good: "addEventListener in useEffect without cleanup in return"

4. **Coverage > Binary**
   - Bad: "Has error handling: yes/no"
   - Good: "Error coverage: 47% (23/49 async ops protected)"

5. **Explanation > Detection**
   - Bad: "Possible infinite loop"
   - Good: "Object in deps changes every render → effect triggers → state updates → re-render → loop"

---

**This document represents the next evolution of UBS:** From pattern matching to semantic understanding. From detection to explanation. From static analysis to **intelligent correlation**.

The future is ast-grep-powered, correlation-aware, consequence-explaining bug analysis.

Let's build it. 🚀
