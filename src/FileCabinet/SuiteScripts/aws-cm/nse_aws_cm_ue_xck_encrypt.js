/**
 * @NApiVersion 2.1
 * @NScriptType usereventscript
 * @NModuleScope SameAccount
 * @NAmdConfig /SuiteScripts/aws-cm/nse_aws_cm_config.json
 *
 * @author Selcuk Dogru
 *
 * @description 
 */
 define(['N/ui/message', 'awsCmLib'], (message, awsCmLib) => {
     const beforeLoad = ({form, type}) => {
         if (type === 'edit') {
            form.addPageInitMessage({
                type: message.Type.WARNING,
                title: 'Credential Data Might Be Corrupted',
                message: 'If you don\'t set the actual Access Key and Secret Key values, saving this record will corrupt the stored credentials.',
                duration: 0
            });
         }
     }

     const beforeSubmit = ({newRecord}) => {
        let accessKeyCipherOut = awsCmLib.encryptKey(newRecord.getValue({fieldId: 'custrecord_nse_aws_cm_ak_access_key'}));
        let secretKeyCipherOut = awsCmLib.encryptKey(newRecord.getValue({fieldId: 'custrecord_nse_aws_cm_ak_secret_key'}));
        
        newRecord.setValue({
            fieldId: 'custrecord_nse_aws_cm_ak_access_key',
            value: accessKeyCipherOut.ciphertext
        });
        newRecord.setValue({
            fieldId: 'custrecord_nse_aws_cm_ak_access_key_iv',
            value: accessKeyCipherOut.iv
        });newRecord.setValue({
            fieldId: 'custrecord_nse_aws_cm_ak_secret_key',
            value: secretKeyCipherOut.ciphertext
        });newRecord.setValue({
            fieldId: 'custrecord_nse_aws_cm_ak_secret_key_iv',
            value: secretKeyCipherOut.iv
        });
     }

     return {
         beforeLoad,
         beforeSubmit
     }
 })