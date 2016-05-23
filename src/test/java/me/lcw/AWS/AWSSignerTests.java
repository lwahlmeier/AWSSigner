package me.lcw.AWS;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import me.lcw.AWS.AWSSigner.AWSParamBuilder;
import me.lcw.AWS.AWSSigner.AWSParams;

public class AWSSignerTests {

  @Test
  public void simpleBuilderTest() {
    String AMZDate = AWSSigner.getAMZDate();
    String NTD = AWSSigner.getNoTimeDate();
    AWSParamBuilder builder = new AWSParamBuilder();
    builder.setHost("simple-host");
    builder.setRegion("test-region");
    builder.setService("test-service");
    builder.setQuery("?test=query");
    builder.setPath("/Test/Path/");
    AWSParams awsParams = builder.build();
    assertEquals("simple-host", awsParams.host);
    assertEquals("test-region", awsParams.region);
    assertEquals("test-service", awsParams.service);
    assertEquals("?test=query", awsParams.query);
    assertEquals("/Test/Path/", awsParams.path);
    assertEquals("GET", awsParams.method);
    builder.setMethod("POST");
    awsParams = builder.build();
    assertEquals("POST", awsParams.method);
    assertEquals(AWSSigner.EMPTY_HASH, awsParams.dataHash);
    builder.setData("TEST".getBytes());
    awsParams = builder.build();
    assertEquals(AWSSigner.getSHA256Hash("TEST"), awsParams.dataHash);
    builder.setAMZDate(AMZDate);
    builder.setNTD(NTD);
    awsParams = builder.build();
    assertEquals(AMZDate, awsParams.AMZDate);
    assertEquals(NTD, awsParams.ntd);
  }
  
  @Test
  public void makeSignKeyCheck() {
    String s = AWSSigner.byteArrayToHex(AWSSigner.getSignatureKey("test", "test", "test"));
    System.out.println(s);
    assertEquals("e3f9ad997b432597bc74617e5bc56bd70ef7e7b71f598e46b85c217bd8ff4027", s);
  }
  
  @Test
  public void makeSimpleSignature() {
    byte[] ba = AWSSigner.getSignatureKey("test", "test", "test");
    AWSParamBuilder builder = new AWSParamBuilder();
    builder.setHost("test");
    builder.setRegion("test");
    builder.setService("test");
    builder.setQuery("test");
    builder.setAMZDate("20160523T122555Z");
    builder.setNTD("20160523");
    
    String s = AWSSigner.makeSignature(ba, builder.build());
    assertEquals("eed16dd14047042b478501b422c226b3f5bc6db7c31dfe8fd3a10cb39ef76fc7", s);
  }
  
  @Test
  public void makeAuthHeader() {
    byte[] ba = AWSSigner.getSignatureKey("test", "test", "test");
    AWSParamBuilder builder = new AWSParamBuilder();
    builder.setHost("test");
    builder.setRegion("test");
    builder.setService("test");
    builder.setQuery("test");
    builder.setAMZDate("20160523T122555Z");
    builder.setNTD("20160523");
    AWSParams awsParams = builder.build();
    String s = AWSSigner.makeSignature(ba, awsParams);
    String s2 = AWSSigner.makeAuthHeader(awsParams, "test", s);
    assertEquals("AWS4-HMAC-SHA256 Credential=test/20160523/test/test/aws4_request, SignedHeaders=host;x-amz-date, Signature=eed16dd14047042b478501b422c226b3f5bc6db7c31dfe8fd3a10cb39ef76fc7", s2);
  }
}
