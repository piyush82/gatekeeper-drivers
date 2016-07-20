```
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

import ch.cyclops.gatekeeper.GKDriver;

import java.util.ArrayList;
import java.util.HashMap;

public class Main
{
    public static void main(String[] args) throws Exception
    {
        GKDriver driver = new GKDriver("/Users/harh/Code/java/gkclient/gatekeeper-driver.conf");
        ArrayList<String> uList = driver.getUserList(0);
        if(uList != null)
        {
            System.out.println("Received user list from Gatekeeper! Count: " + uList.size());
            for(int i=0; i<uList.size(); i++)
                System.out.println("\t" + uList.get(i));
        }

        boolean authResponse = driver.simpleAuthentication(1, "Eq7K8h9gpg");
        if (authResponse)
            System.out.println("Authentication attempt was successful.");
        else
            System.out.println("Authentication attempt failed!");

        String sName = "myservice-"+System.currentTimeMillis();
        HashMap<String, String> newService = driver.registerService(sName, "this is my new cool service", 0);
        String sKey = "";
        if(newService != null)
        {
            System.out.println("Service registration was successful! Got:" + newService.get("uri") + ", Key=" + newService.get("key"));
            sKey = newService.get("key");
        }
        else
        {
            System.out.println("Service registration failed!");
        }

        int newUserId = driver.registerUser("user-"+System.currentTimeMillis(), "pass1234", false, sName, 0);
        if(newUserId != -1)
            System.out.println("User registration was successful. Received new id: " + newUserId);
        else System.out.println("User registration failed!");

        String token = driver.generateToken(newUserId, "pass1234");
        boolean isValidToken = driver.validateToken(token, newUserId);

        if(isValidToken) System.out.println("The token: " + token + " is successfully validated for user-id: " + newUserId);
        else System.out.println("Token validation was unsuccessful! Token: " + token + ", user-id: " + newUserId);

        ArrayList<String> sList = driver.getServiceList(0); //the argument is the starting count of number of allowed
        if(sList != null)
        {
            System.out.println("Received service list from Gatekeeper! Format: name,key Count: " + sList.size());
            for(int i=0; i<sList.size(); i++)
                System.out.println("\t" + sList.get(i));
        }

        isValidToken = driver.validateToken(token, sKey);
        if(isValidToken) System.out.println("The token: " + token + " is successfully validated for user-id: " + newUserId + " against s-key:" + sKey);
        else System.out.println("Token validation was unsuccessful! Token: " + token + ", user-id: " + newUserId + ", s-key: " + sKey);
    }
}
```
