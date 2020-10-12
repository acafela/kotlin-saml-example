package saml.example.core

import org.joda.time.DateTime
import org.opensaml.Configuration
import org.opensaml.common.SAMLVersion
import org.opensaml.saml2.core.*
import org.opensaml.xml.XMLObject
import org.opensaml.xml.io.MarshallingException
import org.opensaml.xml.schema.XSAny
import org.opensaml.xml.schema.XSString
import org.opensaml.xml.schema.impl.XSAnyBuilder
import org.opensaml.xml.security.credential.Credential
import org.opensaml.xml.signature.*
import org.springframework.util.CollectionUtils
import org.springframework.util.StringUtils
import java.util.*
import java.util.function.Consumer
import java.util.stream.Collectors
import javax.xml.namespace.QName

object SAMLBuilder {
    private val builderFactory = Configuration.getBuilderFactory()
    @JvmStatic
	fun <T> buildSAMLObject(objectClass: Class<T>?, qName: QName?): T {
        return builderFactory.getBuilder(qName).buildObject(qName) as T
    }

    @JvmStatic
	fun buildAuthnRequest(acsUrl: String?, protocolBinding: String?, issuer: Issuer?): AuthnRequest {
        val authnRequest = buildSAMLObject(AuthnRequest::class.java, AuthnRequest.DEFAULT_ELEMENT_NAME)
        authnRequest.setIsPassive(true)
        authnRequest.version = SAMLVersion.VERSION_20
        authnRequest.assertionConsumerServiceURL = acsUrl
        authnRequest.protocolBinding = protocolBinding
        authnRequest.issuer = issuer
        authnRequest.issueInstant = DateTime()
        authnRequest.id = UUID.randomUUID().toString()
        return authnRequest
    }

    @JvmStatic
	fun buildIssuer(issuingEntityName: String?): Issuer {
        val issuer = buildSAMLObject(Issuer::class.java, Issuer.DEFAULT_ELEMENT_NAME)
        issuer.value = issuingEntityName
        issuer.format = NameIDType.ENTITY
        return issuer
    }

    private fun buildSubject(subjectNameId: String?, subjectNameIdType: String?, recipient: String?, inResponseTo: String?): Subject {
        val nameID = buildSAMLObject(NameID::class.java, NameID.DEFAULT_ELEMENT_NAME)
        nameID.value = subjectNameId
        nameID.format = subjectNameIdType
        val subject = buildSAMLObject(Subject::class.java, Subject.DEFAULT_ELEMENT_NAME)
        subject.nameID = nameID
        val subjectConfirmation = buildSAMLObject(SubjectConfirmation::class.java,
                SubjectConfirmation.DEFAULT_ELEMENT_NAME)
        subjectConfirmation.method = SubjectConfirmation.METHOD_BEARER
        val subjectConfirmationData = buildSAMLObject(SubjectConfirmationData::class.java,
                SubjectConfirmationData.DEFAULT_ELEMENT_NAME)
        subjectConfirmationData.recipient = recipient
        subjectConfirmationData.inResponseTo = inResponseTo
        subjectConfirmationData.notOnOrAfter = DateTime().plusMinutes(8 * 60)
        subjectConfirmation.subjectConfirmationData = subjectConfirmationData
        subject.subjectConfirmations.add(subjectConfirmation)
        return subject
    }

    fun buildStatus(value: String?): Status {
        val status = buildSAMLObject(Status::class.java, Status.DEFAULT_ELEMENT_NAME)
        val statusCode = buildSAMLObject(StatusCode::class.java, StatusCode.DEFAULT_ELEMENT_NAME)
        statusCode.value = value
        status.statusCode = statusCode
        return status
    }

    @JvmStatic
	fun buildStatus(value: String?, subStatus: String?, message: String?): Status {
        val status = buildStatus(value)
        val subStatusCode = buildSAMLObject(StatusCode::class.java, StatusCode.DEFAULT_ELEMENT_NAME)
        subStatusCode.value = subStatus
        status.statusCode.statusCode = subStatusCode
        val statusMessage = buildSAMLObject(StatusMessage::class.java, StatusMessage.DEFAULT_ELEMENT_NAME)
        statusMessage.message = message
        status.statusMessage = statusMessage
        return status
    }

    @JvmStatic
	fun buildAssertion(principal: SAMLPrincipal, status: Status, entityId: String?): Assertion {
        val assertion = buildSAMLObject(Assertion::class.java, Assertion.DEFAULT_ELEMENT_NAME)
        if (status.statusCode.value == StatusCode.SUCCESS_URI) {
            val subject = buildSubject(principal.nameID, principal.nameIDType,
                    principal.assertionConsumerServiceUrl, principal.requestID)
            assertion.subject = subject
        }
        val issuer = buildIssuer(entityId)
        val audience = buildSAMLObject(Audience::class.java, Audience.DEFAULT_ELEMENT_NAME)
        audience.audienceURI = principal.serviceProviderEntityID
        val audienceRestriction = buildSAMLObject(AudienceRestriction::class.java,
                AudienceRestriction.DEFAULT_ELEMENT_NAME)
        audienceRestriction.audiences.add(audience)
        val conditions = buildSAMLObject(Conditions::class.java, Conditions.DEFAULT_ELEMENT_NAME)
        conditions.notBefore = DateTime().minusMinutes(3)
        conditions.notOnOrAfter = DateTime().plusMinutes(3)
        conditions.audienceRestrictions.add(audienceRestriction)
        assertion.conditions = conditions
        val authnStatement = buildAuthnStatement(DateTime(), entityId)
        assertion.issuer = issuer
        assertion.authnStatements.add(authnStatement)
        assertion.attributeStatements.add(buildAttributeStatement(principal.attributes))
        assertion.id = randomSAMLId()
        assertion.issueInstant = DateTime()

//		Signature signature = (new SignatureBuilder()).buildObject();
////		signature.setSigningCredential(signingCredential);
//		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
//		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
//		assertion.setSignature(signature);
        return assertion
    }

    @JvmStatic
	@Throws(MarshallingException::class, SignatureException::class)
    fun signAssertion(signableXMLObject: SignableXMLObject, signingCredential: Credential?) {
        val signature = buildSAMLObject(Signature::class.java, Signature.DEFAULT_ELEMENT_NAME)
        signature.signingCredential = signingCredential
        signature.signatureAlgorithm = Configuration.getGlobalSecurityConfiguration().getSignatureAlgorithmURI(signingCredential)
        signature.canonicalizationAlgorithm = SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS
        signableXMLObject.signature = signature
        Configuration.getMarshallerFactory().getMarshaller(signableXMLObject).marshall(signableXMLObject)
        Signer.signObject(signature)
    }

    fun getStringValueFromXMLObject(xmlObj: XMLObject?): Optional<String> {
        if (xmlObj is XSString) {
            return Optional.ofNullable(xmlObj.value)
        } else if (xmlObj is XSAny) {
            val xsAny = xmlObj
            val textContent = xsAny.textContent
            if (StringUtils.hasText(textContent)) {
                return Optional.of(textContent)
            }
            val unknownXMLObjects = xsAny.unknownXMLObjects
            if (!CollectionUtils.isEmpty(unknownXMLObjects)) {
                val xmlObject = unknownXMLObjects[0]
                if (xmlObject is NameID) {
                    return Optional.of(xmlObject.value)
                }
            }
        }
        return Optional.empty()
    }

    @JvmStatic
	fun getStringFromXMLObject(xmlObj: XMLObject?): String {
        if (xmlObj is XSString) {
            return xmlObj.value
        } else if (xmlObj is XSAny) {
            val xsAny = xmlObj
            val textContent = xsAny.textContent
            if (StringUtils.hasText(textContent)) {
                return textContent
            }
            val unknownXMLObjects = xsAny.unknownXMLObjects
            if (!CollectionUtils.isEmpty(unknownXMLObjects)) {
                val xmlObject = unknownXMLObjects[0]
                if (xmlObject is NameID) {
                    return xmlObject.value
                }
            }
        }
        return ""
    }

    @JvmStatic
	fun randomSAMLId(): String {
        return "_" + UUID.randomUUID().toString()
    }

    private fun buildAuthnStatement(authnInstant: DateTime, entityID: String?): AuthnStatement {
        val authnContextClassRef = buildSAMLObject(AuthnContextClassRef::class.java,
                AuthnContextClassRef.DEFAULT_ELEMENT_NAME)
        authnContextClassRef.authnContextClassRef = AuthnContext.PASSWORD_AUTHN_CTX
        val authenticatingAuthority = buildSAMLObject(AuthenticatingAuthority::class.java,
                AuthenticatingAuthority.DEFAULT_ELEMENT_NAME)
        authenticatingAuthority.uri = entityID
        val authnContext = buildSAMLObject(AuthnContext::class.java, AuthnContext.DEFAULT_ELEMENT_NAME)
        authnContext.authnContextClassRef = authnContextClassRef
        authnContext.authenticatingAuthorities.add(authenticatingAuthority)
        val authnStatement = buildSAMLObject(AuthnStatement::class.java, AuthnStatement.DEFAULT_ELEMENT_NAME)
        authnStatement.authnContext = authnContext
        authnStatement.authnInstant = authnInstant
        return authnStatement
    }

    private fun buildAttributeStatement(attributes: List<SAMLAttribute?>?): AttributeStatement {
        val attributeStatement = buildSAMLObject(AttributeStatement::class.java,
                AttributeStatement.DEFAULT_ELEMENT_NAME)
        attributes!!.forEach(
                Consumer { entry: SAMLAttribute? -> attributeStatement.attributes.add(buildAttribute(entry.getName(), entry.getValues())) })
        return attributeStatement
    }

    private fun buildAttribute(name: String?, values: List<String?>?): Attribute {
//    XSStringBuilder stringBuilder = (XSStringBuilder) Configuration.getBuilderFactory().getBuilder(XSString.TYPE_NAME);
        val anyBuilder = Configuration.getBuilderFactory().getBuilder(XSAny.TYPE_NAME) as XSAnyBuilder
        val attribute = buildSAMLObject(Attribute::class.java, Attribute.DEFAULT_ELEMENT_NAME)
        attribute.name = name
        //    attribute.setNameFormat("urn:oasis:names:tc:SAML:2.0:attrname-format:uri");
        attribute.nameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
        val xsStringList = values!!.stream().map { value: String? ->
//        XSString stringValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
//        stringValue.setValue(value);
//        return stringValue;
            val anyValue = anyBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSAny.TYPE_NAME)
            anyValue.textContent = value
            anyValue
        }.collect(Collectors.toList())
        attribute.attributeValues.addAll(xsStringList)
        return attribute
    }
}