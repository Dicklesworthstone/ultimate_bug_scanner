import { useCallback, useEffect, useMemo, useState } from "react";

export function CleanHooks({ userId, theme, signal }) {
  const [count, setCount] = useState(0);
  const memoizedConfig = useMemo(() => ({ userId, theme }), [userId, theme]);

  useEffect(() => {
    fetch(`/api/users/${userId}`, { signal });
  }, [userId, signal]);

  const handleClick = useCallback(() => {
    console.log(theme, count);
    setCount((value) => value + 1);
  }, [theme, count]);

  useEffect(() => {
    console.log("apply", memoizedConfig);
  }, [memoizedConfig]);
}
