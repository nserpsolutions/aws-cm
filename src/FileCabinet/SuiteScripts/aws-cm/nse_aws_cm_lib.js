/**
 * @NApiVersion 2.1
 * @NModuleScope Public
 */
 define(['N/crypto', 'N/encode', 'N/runtime', 'N/search', 'N/error', 'N/record', 'nseAws'], (crypto, encode, runtime, search, error, record, nseAws) => {
    const SECRET_ID = 'custsecret_nse_aws_cm_key';

    /**
     * Encrypts a given value using the password stored in API Secrets.
     * 
     * @param {string} value Text to be encrypted
     * @returns {object} Output (ciphertext, iv) of the encrypted value.
     */
    const encryptKey = (value) => {
        let sKey = crypto.createSecretKey({
            secret: SECRET_ID,
            encoding: encode.Encoding.UTF_8
        });

        let cipher = crypto.createCipher({
            algorithm: crypto.EncryptionAlg.AES,
            key: sKey
        });
        cipher.update({
            input: value,
            inputEncoding: encode.Encoding.UTF_8
        });

        return cipher.final({
            outputEncoding: encode.Encoding.HEX
        });
    }

    /**
     * Decrypts a given value using the password stored in API Secrets.
     * 
     * @param {string} value Text to be decrypted
     * @param {string} iv IV generated during encryption
     * @returns {string} Decrypted text
     */
    const decryptKey = (value, iv) => {
        let sKey = crypto.createSecretKey({
            secret: SECRET_ID,
            encoding: encode.Encoding.UTF_8
        });

        let decipher = crypto.createDecipher({
            algorithm: crypto.EncryptionAlg.AES,
            key: sKey,
            iv: iv
        });
        decipher.update({
            input: value,
            inputEncoding: encode.Encoding.HEX
        });

        return decipher.final({
            outputEncoding: encode.Encoding.UTF_8
        });
    }

    /**
     * Finds the available secret from NSE AWS Credential Manager Secrets.
     * 
     * @param {string} secretName Name of the script to be searched
     * @returns {object} Related AWS Credential Manager Access Key, AWS Secret ID (name) and URL values.
     */
    const getSecretDetails = (secretName) => {
        let returnData = {};
        const awsCmSecretsSearch = search.create({
            type: 'customrecord_nse_aws_cm_secrets',
            filters: [
                ['name', 'is', secretName], 'AND', 
                ['custrecord_nse_aws_cm_s_account_id', 'is', runtime.accountId], 'AND', 
                ['custrecord_nse_aws_cm_s_script_id', 'is', runtime.getCurrentScript().id]
            ],
            columns: ['custrecord_nse_aws_cm_s_access_key', 'custrecord_nse_aws_cm_s_secret_id', 'custrecord_nse_aws_cm_s_url']
        });
        awsCmSecretsSearch.run().each((searchResult) => {
            returnData.accessKeyId = searchResult.getValue({name: 'custrecord_nse_aws_cm_s_access_key'});
            returnData.secretId = searchResult.getValue({name: 'custrecord_nse_aws_cm_s_secret_id'});
            returnData.url = searchResult.getValue({name: 'custrecord_nse_aws_cm_s_url'});
        });

        return returnData;
    }

    /**
     * Retrieves AWS credentials from NSE AWS Credential Manager Access Key record and executes Assume Role if necessary.
     * 
     * @param {number} accessKeyId Internal ID of the NSE AWS Credential Manager Access Key record
     * @returns {object} AWS Authorization details.
     */
    const getAwsAuthCredentials = (accessKeyId) => {
        let returnData = {};

        const awsCmAccessKeyRecord = record.load({
            type: 'customrecord_nse_aws_cm_access_keys',
            id: accessKeyId
        });
        returnData.accessKey = decryptKey(awsCmAccessKeyRecord.getValue({fieldId: 'custrecord_nse_aws_cm_ak_access_key'}), awsCmAccessKeyRecord.getValue({fieldId: 'custrecord_nse_aws_cm_ak_access_key_iv'}));
        returnData.secretKey = decryptKey(awsCmAccessKeyRecord.getValue({fieldId: 'custrecord_nse_aws_cm_ak_secret_key'}), awsCmAccessKeyRecord.getValue({fieldId: 'custrecord_nse_aws_cm_ak_secret_key_iv'}));
        returnData.awsRegion = awsCmAccessKeyRecord.getValue({
            fieldId: 'custrecord_nse_aws_cm_ak_region'
        });
        
        const roleArn = awsCmAccessKeyRecord.getValue({
            fieldId: 'custrecord_nse_aws_cm_ak_role_arn'
        });
        if (roleArn !== '') {
            const assumeRoleResponse = nseAws.stsRequests({
                action: 'AssumeRole',
                roleArn: roleArn,
                roleSessionName: awsCmAccessKeyRecord.getValue({fieldId: 'custrecord_nse_aws_cm_ak_role_s_name'}),
                duration: 900,
                payload: '',
                awsRegion: returnData.awsRegion,
                accessKey: returnData.accessKey,
                secretKey: returnData.secretKey
            });
            const assumedRoleCredentials = JSON.parse(assumeRoleResponse.body).AssumeRoleResponse.AssumeRoleResult.Credentials;

            returnData.accessKey = assumedRoleCredentials.AccessKeyId;
            returnData.secretKey = assumedRoleCredentials.SecretAccessKey;
            returnData.sessionToken = assumedRoleCredentials.SessionToken;
        }
        return returnData;
    }

    /**
     * Gets stored credential from AWS Secrets Manager
     * 
     * @param {string} name Name of the NSE AWS Credential Manager Secrets record
     * @returns {string} Stored credential
     */
    const getCredential = (name) => {
        const secretDetails = getSecretDetails(name);
        if (Object.keys(secretDetails).length === 0)
            throw error.create({
                name: 'NSE_AWS_CM_SECRET_NOT_FOUND', 
                message: `No secret found with name ${name} that is available to script ${runtime.getCurrentScript().id} and account ${runtime.accountId}.`
            });
        let smRequestOptions = getAwsAuthCredentials(secretDetails.accessKeyId);
        smRequestOptions.action = 'GetSecretValue';
        smRequestOptions.secretId = secretDetails.secretId;
        
        const smRequestResponse = nseAws.secretsManagerRequests(smRequestOptions);
        return JSON.parse(smRequestResponse.body).SecretString;
    }

    /**
     * Updates stored credential on AWS Secrets Manager
     * 
     * @param {string} name Name of the NSE AWS Credential Manager Secrets record
     * @param {object} credentialContent Key/Value pairs of the credential to be stored
     * @returns {string} Version ID of the updated credential.
     */
    const updateCredential = (name, credentialContent) => {
        const secretDetails = getSecretDetails(name);
        if (Object.keys(secretDetails).length === 0)
            throw error.create({
                name: 'NSE_AWS_CM_SECRET_NOT_FOUND', 
                message: `No secret found with name ${name} that is available to script ${runtime.getCurrentScript().id} and account ${runtime.accountId}.`
            });
        let smRequestOptions = getAwsAuthCredentials(secretDetails.accessKeyId);
        smRequestOptions.action = 'PutSecretValue';
        smRequestOptions.secretId = secretDetails.secretId;
        smRequestOptions.secretString = JSON.stringify(credentialContent).replace(/"/g, '\\"');
        
        const smRequestResponse = nseAws.secretsManagerRequests(smRequestOptions);
        return JSON.parse(smRequestResponse.body).VersionId;
    }

    return {
        encryptKey,
        getCredential,
        updateCredential
    }
 })