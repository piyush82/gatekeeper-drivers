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

import org.apache.commons.configuration.CompositeConfiguration;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.apache.commons.configuration.SystemConfiguration;
import org.apache.log4j.*;

import java.util.ArrayList;

public class Main {
    public static void main(String[] args) throws Exception {
        CompositeConfiguration config = new CompositeConfiguration();
        config.addConfiguration(new SystemConfiguration());
        if (args.length > 0)
            config.addConfiguration(new PropertiesConfiguration(args[args.length - 1]));

        //setting up the logging framework now
        Logger.getRootLogger().getLoggerRepository().resetConfiguration();
        ConsoleAppender console = new ConsoleAppender(); //create appender
        //configure the appender
        String PATTERN = "%d [%p|%c|%C{1}] %m%n";
        console.setLayout(new PatternLayout(PATTERN));
        String logConsoleLevel = config.getProperty("log.level.console").toString();
        switch (logConsoleLevel) {
            case ("INFO"):
                console.setThreshold(Level.INFO);
                break;
            case ("DEBUG"):
                console.setThreshold(Level.DEBUG);
                break;
            case ("WARN"):
                console.setThreshold(Level.WARN);
                break;
            case ("ERROR"):
                console.setThreshold(Level.ERROR);
                break;
            case ("FATAL"):
                console.setThreshold(Level.FATAL);
                break;
            case ("OFF"):
                console.setThreshold(Level.OFF);
                break;
            default:
                console.setThreshold(Level.ALL);
        }

        console.activateOptions();
        //add appender to any Logger (here is root)
        Logger.getRootLogger().addAppender(console);

        String logFileLevel = config.getProperty("log.level.file").toString();
        String logFile = config.getProperty("log.file").toString();
        if(logFile != null && logFile.length() > 0)
        {
            FileAppender fa = new FileAppender();
            fa.setName("FileLogger");

            fa.setFile(logFile);
            fa.setLayout(new PatternLayout("%d %-5p [%c{1}] %m%n"));

            switch (logFileLevel) {
                case ("INFO"):
                    fa.setThreshold(Level.INFO);
                    break;
                case ("DEBUG"):
                    fa.setThreshold(Level.DEBUG);
                    break;
                case ("WARN"):
                    fa.setThreshold(Level.WARN);
                    break;
                case ("ERROR"):
                    fa.setThreshold(Level.ERROR);
                    break;
                case ("FATAL"):
                    fa.setThreshold(Level.FATAL);
                    break;
                case ("OFF"):
                    fa.setThreshold(Level.OFF);
                    break;
                default:
                    fa.setThreshold(Level.ALL);
            }

            fa.setAppend(true);
            fa.activateOptions();

            //add appender to any Logger (here is root)
            Logger.getRootLogger().addAppender(fa);
        }
        //now logger configuration is done, we can start using it.
        Logger mainLogger = Logger.getLogger("gatekeeper-driver.Main");

        mainLogger.debug("Driver loaded properly");
        if(args.length > 0)
        {
            GKDriver gkDriver = new GKDriver(args[args.length - 1]);
            ArrayList<String> uList = gkDriver.getUserList(0); //the argument is the starting count of number of allowed
                                                                //internal attempts.
            if(uList != null)
            {
                mainLogger.info("Received user list from Gatekeeper! Count: " + uList.size());
                for(int i=0; i<uList.size(); i++)
                    mainLogger.info(uList.get(i));
            }

            boolean authResponse = gkDriver.simpleAuthentication(1, "Eq7K8h9gpg");
            if (authResponse)
                mainLogger.info("Authentication attempt was successful.");
            else
                mainLogger.warn("Authentication attempt failed!");
        }
    }
}
