# Addble RSF Proxy

A sample app to setup proxy to integrate with Addble RSF

## Required ENVs

The envs which are required to run this sample application.

| Name             | Description                                                 |
| ---------------- | ----------------------------------------------------------- |
| RSF_URL          | URL for the Addble RSF service                              |
| KEY_ID           | Secret Key ID generated from Addble RSF                     |
| KEY_SECRET       | Secret Key generated from Addble RSF                        |
| SUBSCRIBER_ID    | ONDC Subscriber ID for the NP                               |
| SUBSCRIBER_URI   | ONDC Subscriber URI for the NP                              |
| ONDC_UKID        | Unique Key ID for the private key used to sign ONDC request |
| ONDC_PRIVATE_KEY | Private key used to sign ONDC request                       |

## Request Redirect

For this sample to work, certain paths needs to be redirected to this application.

- `/rsf`
- `/on_settle`
- `/on_report`
- `/recon`
- `/on_recon`
