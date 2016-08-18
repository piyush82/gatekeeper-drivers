/*
 * Copyright (c) 2016. Zuercher Hochschule fuer Angewandte Wissenschaften
 *  All Rights Reserved.
 *
 *     Licensed under the Apache License, Version 2.0 (the "License"); you may
 *     not use this file except in compliance with the License. You may obtain
 *     a copy of the License at
 *
 *          http://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *     WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *     License for the specific language governing permissions and limitations
 *     under the License.
 */

/*
 *     Author: Piyush Harsh,
 *     URL: piyush-harsh.info
 */
package ch.cyclops.gatekeeper;

import okhttp3.*;
import org.apache.commons.configuration.CompositeConfiguration;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.apache.commons.configuration.SystemConfiguration;
import org.apache.log4j.*;
import org.apache.log4j.pattern.IntegerPatternConverter;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;

public class GKDriver
{
    private String gatekeeperUri;
    private int gatekeeperPort;
    private String adminUserId;
    private String adminPassword;
    private Logger driverLogger;
    private boolean internalStatus;
    private String adminToken;

    public static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");
    private int attempCount;

    /**
     * Constructor class, creates the object given the configuration file path.
     * <p>
     * @param confFile  Path to the driver configuration file
     * @param uid   gatekeeper user-id
     * @param pass  gatekeeper account password
     */
    public GKDriver(String confFile, int uid, String pass)
    {
        CompositeConfiguration config = new CompositeConfiguration();
        config.addConfiguration(new SystemConfiguration());
        try
        {
            config.addConfiguration(new PropertiesConfiguration(confFile));
            //now logger configuration is done, we can start using it.
            driverLogger = Logger.getLogger("gatekeeper-driver.Driver");
            gatekeeperUri = config.getProperty("gatekeeper.uri").toString();
            gatekeeperPort = Integer.parseInt(config.getProperty("gatekeeper.port").toString());
            adminUserId = Integer.toString(uid, 10);
            adminPassword = pass;
            internalStatus = true;
            adminToken = "";
            driverLogger.info("gatekeeper driver initialized properly.");
        }
        catch (Exception ex)
        {
            internalStatus = false;
            if(driverLogger != null)
                driverLogger.fatal("Error initializing driver: " + ex.getMessage());
        }
    }

    /**
     * This function gets the list of registered users with Gatekeeper.
     * <p>
     * @param attemptCount int value that allows internal attempts to fulfill the request. Should be a value between 0 and 4
     * @return list of registered users as string ArrayList object, on error a null is returned
     * @throws Exception    an Exception is raised and must be caught or processed
     */
    public ArrayList<String> getUserList(int attemptCount) throws Exception
    {
        OkHttpClient client = new OkHttpClient();
        RequestBody body = RequestBody.create(JSON, "");
        ArrayList<String> result = null;
        attemptCount++;
        //this is an admin only call
        //try first with the available token, if fails then generate a new token
        if(adminToken.length() > 0)
        {
            Request request = new Request.Builder().url(gatekeeperUri + ":" + gatekeeperPort + "/admin/user/").
                    header("User-Agent", "OkHttp Headers.java").addHeader("X-Auth-Token", adminToken).
                    get().build();
            Response response = client.newCall(request).execute();

            driverLogger.info("List User::Response code: " + response.code());

            if(response.code() == 200)
            {
                ResponseBody rBody = response.body();
                JSONObject jsonObj = new JSONObject(rBody.string());
                JSONArray uArray = jsonObj.getJSONArray("userlist");
                JSONArray uidArray = jsonObj.getJSONArray("userids");
                driverLogger.info("Got user-list with : " + uArray.length() + " users.");
                result = new ArrayList<String>(uArray.length());
                for(int i=0; i<uArray.length(); i++)
                {
                    result.add(i, uArray.getString(i) + "," + uidArray.getString(i));
                }
            }
            else
            {
                //something wrong with the token.
                driverLogger.warn("Error probably with the admin-token. Remaking this call automatically. Attempt - " + attemptCount);
                this.adminToken = "";
                if(attemptCount < 5) {
                    response.body().close();
                    return this.getUserList(attemptCount);
                }
                else
                {
                    response.body().close();
                    driverLogger.error("Retry limit reached! Failing gracefully.");
                }
            }
        }
        else
        {
            //generate a new token
            adminToken = generateToken(Integer.parseInt(adminUserId), adminPassword);
            if(adminToken == null) adminToken = "";
            return this.getUserList(attemptCount); //call the function again now that token has been set
        }
        return result;
    }

    /**
     * Allows simple authentication process.
     * <p>
     * @param userId    int value representing the user-id
     * @param password  string value representing user's password
     * @return  true if authentication is successfull, else false is returned.
     * @throws Exception
     */
    public boolean simpleAuthentication(int userId, String password) throws Exception
    {
        OkHttpClient client = new OkHttpClient();

        Request request = new Request.Builder().url(gatekeeperUri + ":" + gatekeeperPort + "/auth/" + userId).
                header("User-Agent", "OkHttp Headers.java").addHeader("X-Auth-Password", password).
                get().build();
        Response response = client.newCall(request).execute();

        driverLogger.info("Authentication Check::Response code: " + response.code());
        if(response.code() == 202)
        {
            response.body().close();
            return true;
        }
        response.body().close();
        return false;
    }

    /**
     * Method to generate a valid token given an userId and corresponding password.
     * <p>
     * @param userId    the user's id
     * @param password  the user's password
     * @return  the token as String, if authentication fails a null is returned.
     * @throws Exception
     */
    public String generateToken(int userId, String password) throws Exception
    {
        OkHttpClient client = new OkHttpClient();
        RequestBody body = RequestBody.create(JSON, "");

        //generate a new token
        Request request = new Request.Builder().url(gatekeeperUri + ":" + gatekeeperPort + "/token/").
                header("User-Agent", "OkHttp Headers.java").addHeader("X-Auth-Password", password).
                addHeader("X-Auth-Uid", Integer.toString(userId)).post(body).build();
        Response response = client.newCall(request).execute();
        driverLogger.info("Request to generate a new token, return code: " + response.code());
        if(response.code() == 200)
        {
            ResponseBody rBody = response.body();

            JSONObject jsonObj = new JSONObject(rBody.string());
            JSONObject temp = new JSONObject(jsonObj.get("token").toString());
            driverLogger.info("Received user-token: " + temp.get("id").toString());
            response.body().close();
            return temp.get("id").toString();
        }
        else
        {
            response.body().close();
            return null;
        }
    }

    /**
     * This method allows registration of a new user with Gatekeeper service. This is an admin-only call.
     * <p>
     * @param username  the desired username
     * @param password  the account password associated with this user
     * @param isAdmin   true if user is an admin-user, else false
     * @param accessList    comma separated list of resources/services this user has access to, use ALL to grant access to everything
     * @param attemptCount  integer value controlling the self execution iterations, should be a value between 0 and 4
     * @return  the user-id as integer if registration is successful, -1 if the process fails.
     * @throws Exception
     */
    public int registerUser(String username, String password, boolean isAdmin, String accessList, int attemptCount) throws Exception
    {
        OkHttpClient client = new OkHttpClient();
        JSONObject callBody = new JSONObject();
        callBody.put("username", username);
        callBody.put("password", password);
        if (isAdmin) callBody.put("isadmin", "y");
        else callBody.put("isadmin", "n");
        callBody.put("accesslist", accessList.trim());
        driverLogger.info("register-user call with json: " + callBody.toString());
        RequestBody body = RequestBody.create(JSON, callBody.toString());
        attemptCount++;

        //this is an admin only call
        //try first with the available token, if fails then generate a new token
        if (adminToken.length() > 0)
        {
            Request request = new Request.Builder().url(gatekeeperUri + ":" + gatekeeperPort + "/admin/user/").
                    header("User-Agent", "OkHttp Headers.java").addHeader("X-Auth-Token", adminToken).
                    post(body).build();

            Response response = client.newCall(request).execute();

            driverLogger.info("Register User::Response code: " + response.code());

            if (response.code() == 200)
            {
                ResponseBody rBody = response.body();
                JSONObject jsonObj = new JSONObject(rBody.string());
                JSONArray uinfoArray = jsonObj.getJSONArray("info");
                JSONObject temp = new JSONObject(uinfoArray.get(0).toString());
                driverLogger.info("Got user-id: " + temp.get("id"));
                response.body().close();
                return Integer.parseInt(temp.get("id").toString());
            }
            response.body().close();
        }
        else
        {
            //generate a new token
            adminToken = generateToken(Integer.parseInt(adminUserId), adminPassword);
            if(adminToken == null) adminToken = "";
            if(attempCount < 5)
                return this.registerUser(username, password, isAdmin, accessList, attemptCount); //call the function again now that token has been set
        }
        return -1;
    }

    /**
     * This method allows an admin user to delete an user identified by user-id
     * <p>
     * @param userId        the user's id whose account is to be deleted from Gatekeeper
     * @param attemptCount  integer value controlling the self execution iterations, should be a value between 0 and 4
     * @return  true if the account was successfully deleted, else false
     * @throws Exception
     */
    public boolean deleteUser(int userId, int attemptCount) throws Exception
    {
        OkHttpClient client = new OkHttpClient();
        attemptCount++;

        //this is an admin only call
        //try first with the available token, if fails then generate a new token
        if (adminToken.length() > 0)
        {
            Request request = new Request.Builder().url(gatekeeperUri + ":" + gatekeeperPort + "/admin/user/" + userId).
                    header("User-Agent", "OkHttp Headers.java").addHeader("X-Auth-Token", adminToken).delete().build();

            Response response = client.newCall(request).execute();

            driverLogger.info("Delete User::Response code: " + response.code());

            if (response.code() == 200)
            {
                response.body().close();
                return true;
            }
            response.body().close();
        }
        else
        {
            //generate a new token
            adminToken = generateToken(Integer.parseInt(adminUserId), adminPassword);
            if(adminToken == null) adminToken = "";
            if(attempCount < 5)
                return this.deleteUser(userId, attemptCount); //call the function again now that token has been set
        }
        return false;
    }

    /**
     * This method allows validation of a token against an user-id, if token is valid and belongs to a claimed user the response is true, else false.
     * <p>
     * @param token     The token which needs to be validated
     * @param userId    user-id to be validated with
     * @return  true if the validation is successful, else a false is returned
     * @throws Exception
     */
    public boolean validateToken(String token, int userId) throws Exception
    {
        OkHttpClient client = new OkHttpClient();

        Request request = new Request.Builder().url(gatekeeperUri + ":" + gatekeeperPort + "/token/validate/" + token).
                header("User-Agent", "OkHttp Headers.java").addHeader("X-Auth-Uid", Integer.toString(userId)).
                get().build();
        Response response = client.newCall(request).execute();

        driverLogger.info("Token Validation::Response code: " + response.code());
        if(response.code() == 200)
        {
            response.body().close();
            return true;
        }
        response.body().close();
        return false;
    }

    /**
     * This method check the token for authorization to use a particular service, if the token is valid, and the user
     * associated with this token has access rights to the service - the respose is true, otherwise a false is returned.
     * <p>
     * @param token     The token which needs to be validated
     * @param serviceKey    The service-key of the service which is requesting the validation of this token
     * @return  true if the user associated with token has access to this service provided the token is valid, false otherwise.
     * @throws Exception
     */
    public boolean validateToken(String token, String serviceKey) throws Exception
    {
        OkHttpClient client = new OkHttpClient();

        Request request = new Request.Builder().url(gatekeeperUri + ":" + gatekeeperPort + "/token/validate/" + token).
                header("User-Agent", "OkHttp Headers.java").addHeader("X-Auth-Service-Key", serviceKey).
                get().build();
        Response response = client.newCall(request).execute();

        driverLogger.info("Token Validation by service::Response code: " + response.code());
        if(response.code() == 200)
        {
            response.body().close();
            return true;
        }
        response.body().close();
        return false;
    }

    /**
     * This admin only method allows admins to get the list of registered services with Gatekeeper. The return array
     * contains service-short-name,service-key as its elements.
     * <p>
     * @param attemptCount integer value controlling the self execution iterations, should be a value between 0 and 4
     * @return list of registered services as string ArrayList object, each element as name,key field, on error a null is returned.
     * @throws Exception
     */
    public ArrayList<String> getServiceList(int attemptCount) throws Exception
    {
        OkHttpClient client = new OkHttpClient();
        RequestBody body = RequestBody.create(JSON, "");
        ArrayList<String> result = null;
        attemptCount++;
        //this is an admin only call
        //try first with the available token, if fails then generate a new token
        if(adminToken.length() > 0)
        {
            Request request = new Request.Builder().url(gatekeeperUri + ":" + gatekeeperPort + "/admin/service/").
                    header("User-Agent", "OkHttp Headers.java").addHeader("X-Auth-Token", adminToken).
                    get().build();
            Response response = client.newCall(request).execute();

            driverLogger.info("List Service::Response code: " + response.code());

            if(response.code() == 200)
            {
                ResponseBody rBody = response.body();
                JSONObject jsonObj = new JSONObject(rBody.string());
                JSONObject sList = new JSONObject(jsonObj.get("servicelist").toString());
                JSONArray sNameList = sList.getJSONArray("shortname");
                JSONArray sKeyList = sList.getJSONArray("service-key");
                driverLogger.info("Got service-list with : " + sNameList.length() + " services.");
                result = new ArrayList<String>(sNameList.length());
                for(int i=0; i<sNameList.length(); i++)
                {
                    result.add(i, sNameList.getString(i) + "," + sKeyList.getString(i));
                }
                response.body().close();
            }
            else
            {
                //something wrong with the token.
                driverLogger.warn("Error probably with the admin-token. Remaking this call automatically. Attempt - " + attemptCount);
                response.body().close();
                this.adminToken = "";
                if(attemptCount < 5)
                    return this.getServiceList(attemptCount);
                else
                {
                    driverLogger.error("Retry limit reached! Failing gracefully.");
                }
            }
        }
        else
        {
            //generate a new token
            adminToken = generateToken(Integer.parseInt(adminUserId), adminPassword);
            if(adminToken == null) adminToken = "";
            if(attemptCount < 5)
                return this.getServiceList(attemptCount); //call the function again now that token has been set
        }
        return result;
    }

    /**
     * This method allows an admin user to register a new service with Gatekeeper, what is returned is a service-uri and
     * service-key. The key should be made available to the service itself for authorizing access to its service, the uri
     * can be stored by admin to manipulate this service representation in Gatekeeper later on.
     * <p>
     * @param shortName     a unique short-name (one-word) for this service being registered, this short-name can be used
     *                      in the access-list of users granting then access to this service.
     * @param description   a sentence describing this service.
     * @param attemptCount  integer value controlling the self execution iterations, should be a value between 0 and 4
     * @return  a HashMap object containing the service uri and the key. null is returned in case of error.
     * @throws Exception
     */
    public HashMap<String, String> registerService(String shortName, String description, int attemptCount) throws Exception
    {
        OkHttpClient client = new OkHttpClient();
        JSONObject callBody = new JSONObject();
        callBody.put("shortname", shortName);
        callBody.put("description", description);
        attemptCount++;

        driverLogger.info("register-service call with json: " + callBody.toString());
        RequestBody body = RequestBody.create(JSON, callBody.toString());

        //this is an admin only call
        //try first with the available token, if fails then generate a new token
        if (adminToken.length() > 0)
        {
            Request request = new Request.Builder().url(gatekeeperUri + ":" + gatekeeperPort + "/admin/service/").
                    header("User-Agent", "OkHttp Headers.java").addHeader("X-Auth-Token", adminToken).
                    post(body).build();

            Response response = client.newCall(request).execute();

            driverLogger.info("Register Service::Response code: " + response.code());

            if (response.code() == 200)
            {
                ResponseBody rBody = response.body();
                JSONObject jsonObj = new JSONObject(rBody.string());
                JSONArray uinfoArray = jsonObj.getJSONArray("info");
                JSONObject temp = new JSONObject(uinfoArray.get(0).toString());
                driverLogger.info("Got service-uri: " + temp.get("service-uri"));
                HashMap<String, String> result = new HashMap<String, String>();
                result.put("uri", temp.getString("service-uri"));
                result.put("key", temp.getString("service-key"));
                response.body().close();
                return result;
            }
            response.body().close();
        }
        else
        {
            //generate a new token
            adminToken = generateToken(Integer.parseInt(adminUserId), adminPassword);
            if(adminToken == null) adminToken = "";
            if(attempCount < 5)
                return this.registerService(shortName, description, attemptCount); //call the function again now that token has been set
        }
        return null;
    }
}
