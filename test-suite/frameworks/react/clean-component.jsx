// ============================================================================
// TEST SUITE: REACT BEST PRACTICES (CLEAN CODE)
// Expected: No React anti-patterns, follows best practices
// ============================================================================

import React, { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";

// GOOD: Proper useEffect dependencies
function UserProfile({ userId }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);

    fetchUser(userId)
      .then((data) => {
        if (!cancelled) {
          setUser(data);
          setLoading(false);
        }
      })
      .catch((error) => {
        if (!cancelled) {
          console.error(error);
          setLoading(false);
        }
      });

    return () => {
      cancelled = true; // Cleanup
    };
  }, [userId]); // Correct dependencies

  if (loading) return <div>Loading...</div>;
  return <div>{user?.name}</div>;
}

// GOOD: Proper state updates
function Counter() {
  const [count, setCount] = useState(0);

  const increment = useCallback(() => {
    setCount((prevCount) => prevCount + 1); // Function form
  }, []);

  const incrementBy = useCallback((amount) => {
    setCount((prevCount) => prevCount + amount);
  }, []);

  return (
    <div>
      <p>Count: {count}</p>
      <button onClick={increment}>+1</button>
      <button onClick={() => incrementBy(5)}>+5</button>
    </div>
  );
}

// GOOD: Using unique, stable keys
function TodoList({ todos }) {
  const handleClick = useCallback((todoId) => {
    console.log("Clicked:", todoId);
  }, []);

  return (
    <ul>
      {todos.map((todo) => (
        <li key={todo.id} onClick={() => handleClick(todo.id)}>
          {todo.text}
        </li>
      ))}
    </ul>
  );
}

// GOOD: Memoizing expensive computations
function ExpensiveComponent({ items, filter }) {
  const filteredItems = useMemo(() => {
    return items.filter(filter);
  }, [items, filter]);

  const total = useMemo(() => {
    return filteredItems.reduce((sum, item) => sum + expensiveCalculation(item), 0);
  }, [filteredItems]);

  return <div>Total: {total}</div>;
}

// GOOD: Proper cleanup in useEffect
function WindowSize() {
  const [size, setSize] = useState({
    width: window.innerWidth,
    height: window.innerHeight,
  });

  useEffect(() => {
    const handleResize = () => {
      setSize({
        width: window.innerWidth,
        height: window.innerHeight,
      });
    };

    window.addEventListener("resize", handleResize);

    // Cleanup function
    return () => {
      window.removeEventListener("resize", handleResize);
    };
  }, []);

  return (
    <div>
      {size.width} x {size.height}
    </div>
  );
}

// GOOD: Using context to avoid prop drilling
const UserContext = React.createContext(null);

function App() {
  const [user, setUser] = useState(null);

  return (
    <UserContext.Provider value={{ user, setUser }}>
      <Level1 />
    </UserContext.Provider>
  );
}

function Level1() {
  return <Level2 />;
}

function Level2() {
  return <Level3 />;
}

function Level3() {
  const { user } = React.useContext(UserContext);
  return <div>{user?.name}</div>;
}

// GOOD: Memoizing child components
const ExpensiveChild = memo(({ data }) => {
  console.log("ExpensiveChild rendered");
  return <div>{JSON.stringify(data)}</div>;
});

function Parent() {
  const [count, setCount] = useState(0);
  const data = useMemo(() => ({ value: "stable" }), []);

  return (
    <div>
      <ExpensiveChild data={data} />
      <button onClick={() => setCount(count + 1)}>Increment: {count}</button>
    </div>
  );
}

// GOOD: Modern refs with useRef
function TextInput() {
  const inputRef = useRef(null);

  const focusInput = useCallback(() => {
    inputRef.current?.focus();
  }, []);

  return (
    <div>
      <input ref={inputRef} type="text" />
      <button onClick={focusInput}>Focus</button>
    </div>
  );
}

// GOOD: Custom hooks for reusable logic
function useDebounce(value, delay) {
  const [debouncedValue, setDebouncedValue] = useState(value);

  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedValue(value);
    }, delay);

    return () => {
      clearTimeout(handler);
    };
  }, [value, delay]);

  return debouncedValue;
}

function SearchComponent() {
  const [query, setQuery] = useState("");
  const debouncedQuery = useDebounce(query, 500);

  useEffect(() => {
    if (debouncedQuery) {
      performSearch(debouncedQuery);
    }
  }, [debouncedQuery]);

  return (
    <input
      type="text"
      value={query}
      onChange={(e) => setQuery(e.target.value)}
      placeholder="Search..."
    />
  );
}

// GOOD: Error boundary
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("Error caught by boundary:", error, errorInfo);
    // Log to error reporting service
  }

  render() {
    if (this.state.hasError) {
      return (
        <div>
          <h2>Something went wrong</h2>
          <details>
            <summary>Error details</summary>
            <pre>{this.state.error?.toString()}</pre>
          </details>
        </div>
      );
    }

    return this.props.children;
  }
}

// GOOD: Form handling with preventDefault
function Form() {
  const [formData, setFormData] = useState({ name: "", email: "" });

  const handleSubmit = useCallback(
    (e) => {
      e.preventDefault();
      console.log("Submitting:", formData);
      submitForm(formData);
    },
    [formData],
  );

  const handleChange = useCallback((e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  }, []);

  return (
    <form onSubmit={handleSubmit}>
      <input name="name" value={formData.name} onChange={handleChange} placeholder="Name" />
      <input
        name="email"
        type="email"
        value={formData.email}
        onChange={handleChange}
        placeholder="Email"
      />
      <button type="submit">Submit</button>
    </form>
  );
}

// GOOD: Computed values instead of derived state
function FullNameComponent({ firstName, lastName }) {
  // Computed in render - no unnecessary state
  const fullName = `${firstName} ${lastName}`;

  return <div>{fullName}</div>;
}

// GOOD: Batching state updates
function MultiUpdate() {
  const [state, setState] = useState({
    name: "",
    email: "",
    age: 0,
  });

  const handleUpdate = useCallback(() => {
    // Single state update
    setState({
      name: "John",
      email: "j@x.com",
      age: 30,
    });
  }, []);

  return <button onClick={handleUpdate}>Update</button>;
}

// GOOD: Stable object dependencies with useMemo
function ConfigComponent({ config }) {
  // Memoize config to avoid unnecessary re-renders
  const stableConfig = useMemo(() => config, [config.host, config.port, config.timeout]);

  useEffect(() => {
    initialize(stableConfig);
  }, [stableConfig]);

  return <div>Initialized</div>;
}

// GOOD: Async updates with cleanup
function AsyncComponent() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const isMountedRef = useRef(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const result = await api.fetch("/endpoint");
        if (isMountedRef.current) {
          setData(result);
        }
      } catch (err) {
        if (isMountedRef.current) {
          setError(err);
        }
      }
    };

    fetchData();

    return () => {
      isMountedRef.current = false;
    };
  }, []);

  if (error) return <div>Error: {error.message}</div>;
  if (!data) return <div>Loading...</div>;
  return <div>{JSON.stringify(data)}</div>;
}

// GOOD: Controlled checkbox with default value
function Checkbox({ checked = false, onChange }) {
  return <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} />;
}

// GOOD: Conditional rendering without hooks
function ConditionalContent({ showContent }) {
  const [count, setCount] = useState(0); // Always called

  if (!showContent) {
    return <div>No content</div>;
  }

  return <div onClick={() => setCount(count + 1)}>Clicks: {count}</div>;
}

// GOOD: Using composition over prop spreading
function Wrapper({ children, className, ...validProps }) {
  // Only spread valid props
  const divProps = Object.keys(validProps).reduce((acc, key) => {
    if (
      ["id", "style", "data-*", "aria-*"].some((valid) => key.startsWith(valid.replace("*", "")))
    ) {
      acc[key] = validProps[key];
    }
    return acc;
  }, {});

  return (
    <div className={className} {...divProps}>
      {children}
    </div>
  );
}

// GOOD: Lazy loading components
const HeavyComponent = React.lazy(() => import("./HeavyComponent"));

function LazyLoadingExample() {
  return (
    <ErrorBoundary>
      <React.Suspense fallback={<div>Loading...</div>}>
        <HeavyComponent />
      </React.Suspense>
    </ErrorBoundary>
  );
}

export {
  App,
  AsyncComponent,
  Checkbox,
  Counter,
  ErrorBoundary,
  ExpensiveComponent,
  Form,
  FullNameComponent,
  LazyLoadingExample,
  Parent,
  SearchComponent,
  TextInput,
  TodoList,
  UserProfile,
  useDebounce,
  WindowSize,
};
