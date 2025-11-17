import java.util.concurrent.CompletableFuture;

public class AsyncErrors {
    public static String loadUser() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> "user");
        return future.handle((result, err) -> {
            if (err != null) {
                throw new IllegalStateException("failed", err);
            }
            return result;
        }).join();
    }

    public static void logChain() {
    CompletableFuture.supplyAsync(() -> "value")
        .handle((result, err) -> {
            if (err != null) {
                System.err.println("chain failed " + err.getMessage());
            } else {
                System.out.println(result.toUpperCase());
            }
            return null;
        })
        .join();
    }

    public static void main(String[] args) {
        loadUser();
        logChain();
    }
}
