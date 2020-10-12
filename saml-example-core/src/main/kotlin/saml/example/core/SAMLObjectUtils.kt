package saml.example.core

import org.opensaml.Configuration
import org.opensaml.common.SAMLObject
import org.opensaml.xml.io.MarshallingException
import org.slf4j.LoggerFactory
import org.w3c.dom.Element
import org.w3c.dom.ls.DOMImplementationLS

object SAMLObjectUtils {
    private val LOG = LoggerFactory.getLogger(SAMLObjectUtils::class.java)
    @JvmStatic
    fun samlObjectToString(`object`: SAMLObject): String {
        return try {
            val ele = samlObjectToElement(`object`)
            elementToString(ele)
        } catch (e: MarshallingException) {
            LOG.warn("Failed to SAMLObject to String.", e)
            ""
        } catch (e: IllegalArgumentException) {
            LOG.warn("Failed to SAMLObject to String.", e)
            ""
        }
    }

    @Throws(MarshallingException::class)
    private fun samlObjectToElement(`object`: SAMLObject): Element? {
        var element: Element? = null
        element = try {
            val unMarshallerFactory = Configuration.getMarshallerFactory()
            val marshaller = unMarshallerFactory.getMarshaller(`object`)
            marshaller.marshall(`object`)
        } catch (e: ClassCastException) {
            throw IllegalArgumentException("The class does not implement the interface XMLObject", e)
        }
        return element
    }

    private fun elementToString(ele: Element?): String {
        val document = ele!!.ownerDocument
        val domImplLS = document.implementation as DOMImplementationLS
        val serializer = domImplLS.createLSSerializer()
        return serializer.writeToString(ele)
    }
}