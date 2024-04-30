import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

public class TsunamiHostnameVerifier implements HostnameVerifier {
  public boolean verify(String arg0, SSLSession arg1) {
    return true;
  }
}
;
