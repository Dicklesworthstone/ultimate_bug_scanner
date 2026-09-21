import { useCallback, useEffect, useMemo, useState } from "react";

export function BuggyHooks({ userId, theme }) {
  const [count, setCount] = useState(0);
  const config = { userId, theme };

  useEffect(() => {
    fetch(`/api/users/${userId}`);
  }, []);

  const handleClick = useCallback(() => {
    console.log(theme, count);
  }, []);

  const memoizedConfig = useMemo(() => ({ config }), [config]);

  useEffect(() => {
    console.log("apply", memoizedConfig);
  }, [memoizedConfig]);
}
