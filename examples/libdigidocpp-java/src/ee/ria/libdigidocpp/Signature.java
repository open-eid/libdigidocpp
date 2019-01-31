/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 3.0.12
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */

package ee.ria.libdigidocpp;

public class Signature {
  private transient long swigCPtr;
  protected transient boolean swigCMemOwn;

  protected Signature(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  protected static long getCPtr(Signature obj) {
    return (obj == null) ? 0 : obj.swigCPtr;
  }

  protected void finalize() {
    delete();
  }

  public synchronized void delete() {
    if (swigCPtr != 0) {
      if (swigCMemOwn) {
        swigCMemOwn = false;
        digidocJNI.delete_Signature(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  static public class Validator {
    private transient long swigCPtr;
    protected transient boolean swigCMemOwn;
  
    protected Validator(long cPtr, boolean cMemoryOwn) {
      swigCMemOwn = cMemoryOwn;
      swigCPtr = cPtr;
    }
  
    protected static long getCPtr(Validator obj) {
      return (obj == null) ? 0 : obj.swigCPtr;
    }
  
    protected void finalize() {
      delete();
    }
  
    public synchronized void delete() {
      if (swigCPtr != 0) {
        if (swigCMemOwn) {
          swigCMemOwn = false;
          digidocJNI.delete_Signature_Validator(swigCPtr);
        }
        swigCPtr = 0;
      }
    }
  
    public Validator(Signature s) {
      this(digidocJNI.new_Signature_Validator(Signature.getCPtr(s), s), true);
    }
  
    public String diagnostics() {
      return digidocJNI.Signature_Validator_diagnostics(swigCPtr, this);
    }
  
    public Signature.Validator.Status status() {
      return Signature.Validator.Status.swigToEnum(digidocJNI.Signature_Validator_status(swigCPtr, this));
    }
  
    public final static class Status {
      public final static Signature.Validator.Status Valid = new Signature.Validator.Status("Valid");
      public final static Signature.Validator.Status Warning = new Signature.Validator.Status("Warning");
      public final static Signature.Validator.Status NonQSCD = new Signature.Validator.Status("NonQSCD");
      public final static Signature.Validator.Status Test = new Signature.Validator.Status("Test");
      public final static Signature.Validator.Status Invalid = new Signature.Validator.Status("Invalid");
      public final static Signature.Validator.Status Unknown = new Signature.Validator.Status("Unknown");
  
      public final int swigValue() {
        return swigValue;
      }
  
      public String toString() {
        return swigName;
      }
  
      public static Status swigToEnum(int swigValue) {
        if (swigValue < swigValues.length && swigValue >= 0 && swigValues[swigValue].swigValue == swigValue)
          return swigValues[swigValue];
        for (int i = 0; i < swigValues.length; i++)
          if (swigValues[i].swigValue == swigValue)
            return swigValues[i];
        throw new IllegalArgumentException("No enum " + Status.class + " with value " + swigValue);
      }
  
      private Status(String swigName) {
        this.swigName = swigName;
        this.swigValue = swigNext++;
      }
  
      private Status(String swigName, int swigValue) {
        this.swigName = swigName;
        this.swigValue = swigValue;
        swigNext = swigValue+1;
      }
  
      private Status(String swigName, Status swigEnum) {
        this.swigName = swigName;
        this.swigValue = swigEnum.swigValue;
        swigNext = this.swigValue+1;
      }
  
      private static Status[] swigValues = { Valid, Warning, NonQSCD, Test, Invalid, Unknown };
      private static int swigNext = 0;
      private final int swigValue;
      private final String swigName;
    }
  
  }

  public static String getPOLv1() {
    return digidocJNI.Signature_POLv1_get();
  }

  public static String getPOLv2() {
    return digidocJNI.Signature_POLv2_get();
  }

  public String id() {
    return digidocJNI.Signature_id(swigCPtr, this);
  }

  public String claimedSigningTime() {
    return digidocJNI.Signature_claimedSigningTime(swigCPtr, this);
  }

  public String trustedSigningTime() {
    return digidocJNI.Signature_trustedSigningTime(swigCPtr, this);
  }

  public String signatureMethod() {
    return digidocJNI.Signature_signatureMethod(swigCPtr, this);
  }

  public void validate() {
    digidocJNI.Signature_validate__SWIG_0(swigCPtr, this);
  }

  public byte[] dataToSign() {
    return digidocJNI.Signature_dataToSign(swigCPtr, this);
  }

  public void setSignatureValue(byte[] signatureValue) {
    digidocJNI.Signature_setSignatureValue(swigCPtr, this, signatureValue);
  }

  public void extendSignatureProfile(String profile) {
    digidocJNI.Signature_extendSignatureProfile(swigCPtr, this, profile);
  }

  public String policy() {
    return digidocJNI.Signature_policy(swigCPtr, this);
  }

  public String SPUri() {
    return digidocJNI.Signature_SPUri(swigCPtr, this);
  }

  public String profile() {
    return digidocJNI.Signature_profile(swigCPtr, this);
  }

  public String city() {
    return digidocJNI.Signature_city(swigCPtr, this);
  }

  public String stateOrProvince() {
    return digidocJNI.Signature_stateOrProvince(swigCPtr, this);
  }

  public String postalCode() {
    return digidocJNI.Signature_postalCode(swigCPtr, this);
  }

  public String countryName() {
    return digidocJNI.Signature_countryName(swigCPtr, this);
  }

  public StringVector signerRoles() {
    return new StringVector(digidocJNI.Signature_signerRoles(swigCPtr, this), true);
  }

  public String OCSPProducedAt() {
    return digidocJNI.Signature_OCSPProducedAt(swigCPtr, this);
  }

  public String TimeStampTime() {
    return digidocJNI.Signature_TimeStampTime(swigCPtr, this);
  }

  public String ArchiveTimeStampTime() {
    return digidocJNI.Signature_ArchiveTimeStampTime(swigCPtr, this);
  }

  public String streetAddress() {
    return digidocJNI.Signature_streetAddress(swigCPtr, this);
  }

  public String signedBy() {
    return digidocJNI.Signature_signedBy(swigCPtr, this);
  }

  public void validate(String policy) {
    digidocJNI.Signature_validate__SWIG_1(swigCPtr, this, policy);
  }

  public byte[] messageImprint() {
    return digidocJNI.Signature_messageImprint(swigCPtr, this);
  }

  public byte[] signingCertificateDer() {
    return digidocJNI.Signature_signingCertificateDer(swigCPtr, this);
  }

  public byte[] OCSPCertificateDer() {
    return digidocJNI.Signature_OCSPCertificateDer(swigCPtr, this);
  }

  public byte[] TimeStampCertificateDer() {
    return digidocJNI.Signature_TimeStampCertificateDer(swigCPtr, this);
  }

  public byte[] ArchiveTimeStampCertificateDer() {
    return digidocJNI.Signature_ArchiveTimeStampCertificateDer(swigCPtr, this);
  }

}
