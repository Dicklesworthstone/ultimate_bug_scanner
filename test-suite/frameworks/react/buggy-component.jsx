// ============================================================================
// TEST SUITE: REACT ANTI-PATTERNS (BUGGY CODE)
// Expected: 25+ WARNING/CRITICAL issues - Common React mistakes
// ============================================================================

import React, { useCallback, useEffect, useState } from "react";

// BUG 1: Missing dependency in useEffect
function UserProfile({ userId }) {
  const [user, setUser] = useState(null);

  useEffect(() => {
    fetchUser(userId).then(setUser);
  }, []); // Missing userId dependency!

  return <div>{user?.name}</div>;
}

// BUG 2: Setting state directly
class Counter extends React.Component {
  constructor(props) {
    super(props);
    this.state = { count: 0 };
  }

  increment() {
    this.state.count++; // WRONG! Mutates state directly
    this.forceUpdate(); // Anti-pattern
  }

  render() {
    return <button onClick={() => this.increment()}>{this.state.count}</button>;
  }
}

// BUG 3: Inline function in render (creates new function every render)
function TodoList({ todos }) {
  return (
    <ul>
      {todos.map((todo, index) => (
        <li key={index} onClick={() => handleClick(todo)}>
          {todo.text}
        </li>
      ))}
    </ul>
  );
}

// BUG 4: Using array index as key
function Items({ items }) {
  return items.map((item, index) => (
    <div key={index}>{item.name}</div> // Bad! Causes issues when reordering
  ));
}

// BUG 5: Updating state based on previous state incorrectly
function ClickCounter() {
  const [count, setCount] = useState(0);

  const handleClick = () => {
    setCount(count + 1); // May be stale!
    setCount(count + 1); // Won't increment by 2
  };

  return <button onClick={handleClick}>{count}</button>;
}

// BUG 6: Memory leak - no cleanup in useEffect
function DataFetcher({ url }) {
  const [data, setData] = useState(null);

  useEffect(() => {
    fetchData(url).then(setData);
    // Component might unmount before fetch completes
    // Should: check if mounted or use AbortController
  }, [url]);

  return <div>{data}</div>;
}

// BUG 7: Calling hooks conditionally
function ConditionalHook({ condition }) {
  if (condition) {
    useState(0); // WRONG! Hooks must be called unconditionally
  }

  return <div>Content</div>;
}

// BUG 8: Not memoizing expensive computations
function ExpensiveComponent({ items }) {
  // Recalculates on every render!
  const total = items.reduce((sum, item) => sum + expensiveCalculation(item), 0);

  return <div>Total: {total}</div>;
}

// BUG 9: Props mutation
function TodoItem({ todo }) {
  const handleComplete = () => {
    todo.completed = true; // WRONG! Mutates props
    forceUpdate();
  };

  return <div onClick={handleComplete}>{todo.text}</div>;
}

// BUG 10: Forgetting to bind this in class components
class Button extends React.Component {
  handleClick() {
    console.log(this.props.label); // 'this' will be undefined!
  }

  render() {
    return <button onClick={this.handleClick}>{this.props.label}</button>;
  }
}

// BUG 11: setState in render
class BadComponent extends React.Component {
  render() {
    if (this.state.needsUpdate) {
      this.setState({ needsUpdate: false }); // Causes infinite loop!
    }
    return <div>Content</div>;
  }
}

// BUG 12: Not cleaning up event listeners
function WindowSize() {
  const [size, setSize] = useState({ width: 0, height: 0 });

  useEffect(() => {
    const handleResize = () => {
      setSize({ width: window.innerWidth, height: window.innerHeight });
    };

    window.addEventListener("resize", handleResize);
    // Missing cleanup!
  }, []);

  return (
    <div>
      {size.width} x {size.height}
    </div>
  );
}

// BUG 13: Prop drilling (not a bug per se, but anti-pattern)
function App() {
  const [user, setUser] = useState(null);
  return <Level1 user={user} setUser={setUser} />;
}

function Level1({ user, setUser }) {
  return <Level2 user={user} setUser={setUser} />;
}

function Level2({ user, setUser }) {
  return <Level3 user={user} setUser={setUser} />;
}

function Level3({ user, setUser }) {
  return <div>{user?.name}</div>;
}

// BUG 14: Unnecessary re-renders
function Parent() {
  const [count, setCount] = useState(0);

  return (
    <div>
      <ExpensiveChild data={someComplexData} />
      <button onClick={() => setCount(count + 1)}>Increment</button>
    </div>
  );
  // ExpensiveChild re-renders even though data doesn't change
}

// BUG 15: String refs (deprecated)
class OldStyleRefs extends React.Component {
  handleClick() {
    this.refs.myInput.focus(); // Deprecated!
  }

  render() {
    return <input ref="myInput" />;
  }
}

// BUG 16: Incorrect useCallback dependencies
function SearchComponent({ onSearch }) {
  const [query, setQuery] = useState("");

  const handleSearch = useCallback(() => {
    onSearch(query);
  }, []); // Missing query dependency!

  return <input onChange={(e) => setQuery(e.target.value)} />;
}

// BUG 17: Nested component definitions
function Outer() {
  // WRONG! Inner component recreated on every render
  function Inner({ value }) {
    return <div>{value}</div>;
  }

  return <Inner value="test" />;
}

// BUG 18: Not preventing default in forms
function Form() {
  const handleSubmit = (e) => {
    // Missing e.preventDefault()
    console.log("Submitting...");
    // Page will reload!
  };

  return (
    <form onSubmit={handleSubmit}>
      <button type="submit">Submit</button>
    </form>
  );
}

// BUG 19: Derived state that should be computed
function FullNameComponent({ firstName, lastName }) {
  const [fullName, setFullName] = useState("");

  useEffect(() => {
    setFullName(`${firstName} ${lastName}`);
  }, [firstName, lastName]);
  // Unnecessary state! Should just compute in render

  return <div>{fullName}</div>;
}

// BUG 20: Multiple state updates causing multiple renders
function MultiUpdate() {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [age, setAge] = useState(0);

  const handleUpdate = () => {
    setName("John"); // Render 1
    setEmail("j@x.com"); // Render 2
    setAge(30); // Render 3
    // Should batch these or use single state object
  };

  return <button onClick={handleUpdate}>Update</button>;
}

// BUG 21: useEffect with object dependency
function ObjectDependency({ config }) {
  useEffect(() => {
    initialize(config);
  }, [config]); // config is object, will trigger on every render if not memoized

  return <div>Initialized</div>;
}

// BUG 22: Async setState race condition
function AsyncUpdate() {
  const [data, setData] = useState(null);

  const fetchData = async () => {
    const result1 = await api.fetch("/endpoint1");
    setData(result1);
    const result2 = await api.fetch("/endpoint2");
    setData(result2); // If component unmounts between calls, this crashes
  };

  useEffect(() => {
    fetchData();
  }, []);

  return <div>{data}</div>;
}

// BUG 23: Boolean prop without default
function Checkbox({ checked, onChange }) {
  // If checked is undefined, checkbox becomes uncontrolled
  return <input type="checkbox" checked={checked} onChange={onChange} />;
}

// BUG 24: Using findDOMNode (deprecated)
class LegacyComponent extends React.Component {
  componentDidMount() {
    const node = ReactDOM.findDOMNode(this); // Deprecated!
    node.focus();
  }

  render() {
    return <div>Content</div>;
  }
}

// BUG 25: Not handling errors with Error Boundaries
function RiskyComponent({ data }) {
  // No error boundary wrapping this
  return <div>{data.someProperty.that.might.not.exist}</div>;
}

// BUG 26: Spreading all props blindly
function Wrapper(props) {
  return <div {...props} />; // Could pass invalid HTML attributes
}

// BUG 27: Using componentWillMount (deprecated)
class DeprecatedLifecycle extends React.Component {
  componentWillMount() {
    // Deprecated! Use componentDidMount or constructor
    this.fetchData();
  }

  render() {
    return <div>Content</div>;
  }
}

// BUG 28: Infinite loop with useEffect
function InfiniteLoop() {
  const [data, setData] = useState([]);

  useEffect(() => {
    setData([...data, "new item"]); // Causes infinite loop!
  }, [data]); // data changes, triggers effect, changes data again...

  return (
    <ul>
      {data.map((item, i) => (
        <li key={i}>{item}</li>
      ))}
    </ul>
  );
}

export {
  BadComponent,
  Button,
  ClickCounter,
  ConditionalHook,
  Counter,
  DataFetcher,
  ExpensiveComponent,
  Items,
  TodoItem,
  TodoList,
  UserProfile,
  WindowSize,
};
