import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.io.FileInputStream;
import java.io.IOException;

public class ResourceLifecycle {
    public void leak() {
        ExecutorService exec = Executors.newSingleThreadExecutor();
        exec.submit(() -> System.out.println("work"));
        // missing exec.shutdown()
    }

    public void leakStream() throws IOException {
        FileInputStream in = new FileInputStream("/tmp/data.txt");
        System.out.println(in.read());
        // missing in.close()
    }
}
