# 2 Main concerns in email analysis
- Security issues
	- Identify suspicious/abnormal/malicious patterns in emails
- Perfomance issues
	- Identify delivery and delay issues in emails

# Security issues
- Social engineering
	- psychological manipulation of people into performing or divulging info by exploiting weaknesses in human nature
	- these "weaknesses" can be curiosity, jealousy, greed, kindness, willingness to help
- Phishing
	- sub-section of social engineering delivered through email to trick someone into either revealing personal info and credentials of executing malicious code on thier computer
	- Phishing emails will usually appear to come from a trusted source, whether that's a person or a business. They include content that tries to tempt or trick people into downloading software, opening attachments, or following links to a bogus website

# Email header structure

| **Field** | **Details** |
|---|---|
| **From** | The sender's address |
| **To** | The receiver's address, including CC and BCC. |
| **Date** | Timestamp, when the email was **sent.** |
| **Subject** | The subject of the email. |
| **Return Path** | The return address of the reply, a.k.a. "Reply-To". If you reply to an email, the reply will go to the address mentioned in this field.
| **Domain Key and DKIM Signatures** | Email signatures are provided by email services to identify and authenticate emails.
| **SPF** | Shows the server that was used to send the email. It will help to understand if the actual server is used to send the email from a specific domain.
| **Message-ID** | Unique ID of the email. |
| **MIME-Version** | Used MIME version. It will help to understand the delivered "non-text" contents and attachments. |
| **X-Headers** | The receiver mail providers usually add these fields. Provided info is usually experimental and can be different according to the mail provider. |
| **X-Received** | Mail servers that the email went through. |
| **X-Spam Status** | Spam score of the email. |
| **X-Mailer** |  Email client name. |

# Important Email Header Fields for Quick Analysis

| **Field** | **Details** |
| --- | --- |
|**From** | The sender's address. |
| **To** | The receiver's address, including CC and BCC. |
| **Date** | Timestamp, when the email was **sent.** |
| **Subject** | The subject of the email. |
| **Return Path** | The return address of the reply, a.k.a. "Reply-To". If you reply to an email, the reply will go to the address mentioned in this field. |
| **Domain Key and DKIM Signatures** | Email signatures are provided by email services to identify and authenticate emails. |
| **SPF** | Shows the server that was used to send the email. It will help to understand if the actual server is used to send the email from a specific domain. |
| **Message-ID** | Unique ID of the email. |
| **MIME-Version** | Used MIME version. It will help to understand the delivered "non-text" contents and attachments. |
| **X-Headers** | The receiver mail providers usually add these fields. Provided info is usually experimental and can be different according to the mail provider. |
| **X-Received** | Mail servers that the email went through. |
| **X-Spam Status** | Spam score of the email. |
|  **X-Mailer** | Email client name. |

