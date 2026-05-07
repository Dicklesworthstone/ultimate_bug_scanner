import { useRouter, useSearchParams } from "next/navigation";

function isSafeRedirectPath(value: string): boolean {
  return value.startsWith("/") && !value.startsWith("//");
}

export function LoginRedirectButton() {
  const router = useRouter();
  const searchParams = useSearchParams();

  function handleLoginSuccess(): void {
    const returnTo = searchParams.get("returnTo") || "/";
    if (isSafeRedirectPath(returnTo)) {
      router.push(returnTo);
      return;
    }
    router.push("/");
  }

  return <button onClick={handleLoginSuccess}>Continue</button>;
}
