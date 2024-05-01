import java.net.HttpURLConnection;
import java.net.URL;
import javax.net.ssl.HttpsURLConnection;

public class Tsunami {

  public static void main(String[] args) throws Exception {

    // Create and set all-trusting host name verifier to avoid certificate issues
    HttpsURLConnection.setDefaultHostnameVerifier(new TsunamiHostnameVerifier());
    // Create HTTP request to resource
    URL url = new URL(args[0]);
    HttpURLConnection con = (HttpURLConnection) url.openConnection();
    con.getInputStream();
  }
}
