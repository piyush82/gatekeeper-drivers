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
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;

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

    /**
     * Constructor class, creates the object given the configuration file path.
     * <p>
     * @param confFile  Path to the driver configuration file
     */
    public GKDriver(String confFile)
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
            adminUserId = config.getProperty("gatekeeper.admin.user.id").toString();
            adminPassword = config.getProperty("gatekeeper.admin.password").toString();
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
     * @param attemptCount int value that allows internal attempts to fulfill the request. Usually 0
     * @return list of registered users as string ArrayList object, on error a null is returned
     * @throws Exception    an Exception is raised and must be caught or processed
     */
    public ArrayList<String> getUserList(int attemptCount) throws Exception
    {
        OkHttpClient client = new OkHttpClient();
        RequestBody body = RequestBody.create(JSON, "");
        ArrayList<String> result = null;
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
                driverLogger.info("Got user-list with : " + uArray.length() + " users.");
                result = new ArrayList<String>(uArray.length());
                for(int i=0; i<uArray.length(); i++)
                {
                    result.add(i, uArray.getString(i));
                }
            }
            else
            {
                //something wrong with the token.
                attemptCount++;
                driverLogger.warn("Error probably with the admin-token. Remaking this call automatically. Attempt - " + attemptCount);
                this.adminToken = "";
                if(attemptCount < 5)
                    return this.getUserList(attemptCount);
                else
                {
                    driverLogger.error("Retry limit reached! Failing gracefully.");
                }
            }
        }
        else
        {
            //generate a new token
            Request request = new Request.Builder().url(gatekeeperUri + ":" + gatekeeperPort + "/token/").
                    header("User-Agent", "OkHttp Headers.java").addHeader("X-Auth-Password", adminPassword).
                    addHeader("X-Auth-Uid", adminUserId).post(body).build();
            Response response = client.newCall(request).execute();
            driverLogger.info("Request to generate a new token: " + response.code());
            ResponseBody rBody = response.body();
            //driverLogger.info(rBody.string());
            JSONObject jsonObj = new JSONObject(rBody.string());
            JSONObject temp = new JSONObject(jsonObj.get("token").toString());
            driverLogger.info("Received admin-token: " + temp.get("id").toString());
            adminToken = temp.get("id").toString();
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
        if(response.code() == 202) return true;

        return false;
    }

}
