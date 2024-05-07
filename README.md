# Azure
This project goes over configuring a VM in Azure to provide custom logs to display geographical data in MS Sentinel. Implemented a custom PowerShell script to extract metadata from Windows Event Viewer and forward to an API.

### **Project Scope -**

- Configure an Azure virtual machine
- Implement a custom PowerShell script to extract metadata from Windows Event Viewer and forward to an API
- Configure Log Analytics Workspace to create custom logs
- Configure custom fields in LAW with the intent of mapping geo data in Azure Sentinel
- Configure Azure Sentinel to display global attack data on world map (RDP Brute Force)

---

Let's get started. First, I created an Azure account, and navigated to [portal.azure.com](http://portal.azure.com/). I realized quickly cloud services get expensive fast - thankfully, Microsoft Azure offers $200 credit for their services to start. This won't cost you anything for a while, but over a long period of time, that $200 credit will drain if you keep this project up and running. So, FYI, utilize your time wisely unless you have the money to spend! (You can remove the Resource Groups associated with this lab at the end of this project if you don't want to get charged.)

Second, I created a Virtual Machine in Azure. You can search this in the search bar at the top. Then click **create** > **Azure virtual machine.**

Then, I created a new "Resource Group". A resource group is simply a container that contains all the related resources for an Azure solution. I named mine "Beesnest" because, well, it's appropriate. I configured it to spawn in a region near me, as well as run Windows 10 Pro. I began to then create the credentials for the admin account I'm using to log into windows. I selected “**Allow selected ports**" and "**RDP (3389)**" under "Select inbound ports". This ensures that RDP requests will be allowed to flow to our honeypot.

I deleted the default inbound rule, and then created my own. I purposely selected every possible setting to allow ANY traffic, with ANY protocol, to ANY destination. As you can probably guess, this allows all traffic to enter the VM. After saving my settings, I wait for Azure to validate and deploy my VM. Awesome.

Now onto the meat of the matter. LAW (Log Analytics Workspace) is where we'll execute our PowerShell query to extract the metadata we want. I selected my resource group to be the same as the one I created earlier (Beesnest). Under the “Instance Details” section, I made sure to select my desired region, then created the LAW.

After this, I navigated to Microsoft Defender for Cloud, and enabled then plan for all my servers and SQL servers. Under “Data collection”, I make sure "**All Events**" is selected, and save my configuration. 

While I began connecting to my VM, I added Microsoft Sentinel to my Azure workspace. Remember, we’re using RDP (Remote Desktop Protocol), so I open it on my local machine to connect to my Azure VM. Here, I purposely entered my credentials incorrectly a few times, to ensure I can view this exact event in Event Viewer for later. 

Upon viewing Windows Event Viewer, I could see under what’s classified as “Audit Failure”, I could see failed login attempts, to which account, and for what reason. In this case, it was simply for the incorrect username and password. The purpose of this lab is to **bait any and all failed RDP connection attempts from across the globe, and view exactly where they’re coming from.** After discovering an exposed RDP service, malicious actors initiate login attempts in hopes of gaining unauthorized access to the system. 

The next course of action is to accept ICMP echo requests. We can do this by simply navigating to Windows Firewall, and turning it off.  We can verify this by pinging the VM from our host machine (ping [address] -t).

Next is our custom PowerShell script. I copied said script from here: https://github.com/joshmadakor1/Sentinel-Lab/blob/main/Custom_Security_Log_Exporter.ps1

Upon analyzing the PowerShell code, you will notice an API token listed at the top. I grabbed my own API key from https://ipgeolocation.io/. Unfortunately, you only get 1000 free API requests before the token stops working for the day, but it should be enough for demonstrative purposes. (Next cheapest plan is $15/mo for up to 150,000 requests, if you happen to be interested. That website isn’t the only option though!) After creating your account and generating your API token, paste it into the $API_KEY field in the appropriate field in PowerShell.

To put it very simply, the PowerShell script will scan through Windows Event Log, note all events of failed login attempts via RDP, grab the IP and create geographical data. The log will be saved in C:\ProgramData\failed_rdp.log.

If you run the script on your VM, you already might see some entries for failed login attempts.

Back to our LAW. I created a “New custom log (MMA-based)” under the “Tables” category. It will ask for a sample log file, which is where you feed it the aforementioned failed_rdp.log file from your VM.

After leaving my “Record delimiter” settings default, I specified the Collection Path to be the same file location as my failed_rdp.log. This is where the VM will log data from. I named my custom log name as “FAILED_RDP_WITH_GEO”. 

After creating the log, I now want to build the query that parses our log files to output the appropriate data we need to populate the map in MS Sentinel. 

Navigating to Azure’s MS Sentinel, I went under the “Workbooks” section, and created a new one. I added a query widget, and pasted the query inside of it. 

The query we’re running is this: 

`FAILED_RDP_WITH_GEO_CL | extend username = extract(@"username:([^,]+)", 1, RawData), timestamp = extract(@"timestamp:([^,]+)", 1, RawData), latitude = extract(@"latitude:([^,]+)", 1, RawData), longitude = extract(@"longitude:([^,]+)", 1, RawData), sourcehost = extract(@"sourcehost:([^,]+)", 1, RawData), state = extract(@"state:([^,]+)", 1, RawData), label = extract(@"label:([^,]+)", 1, RawData), destination = extract(@"destinationhost:([^,]+)", 1, RawData), country = extract(@"country:([^,]+)", 1, RawData) | where destination != "samplehost" | where sourcehost != "" | summarize event_count=count() by timestamp, label, country, state, sourcehost, username, destination, longitude, latitude`

Under the “Visualization” drop-down menu, select “Map”. This will display all queried data on a map. Shocker! 

Again, it may take some time for custom log data to sync in Azure, so give it some time if nothing happens when clicking “Run”. 

And there we go. Almost immediately after this is initiated, I personally was receiving tons of requests from Poland, Brazil, and in particular, Shanghai, China. This is where 80% of the traffic was coming from at the time of documenting this project. 

You can peer back into your VM and view the PowerShell script running in real-time, and seeing usernames, IP addresses and even latitude/longitude coordinates. 

This entire project was incredibly fascinating to me. This is a firsthand, hands-on witnessing of threat actor activity, despite being very simple to set up. I was surprised at not only how quickly the requests were pouring in, but also the sheer amount of requests I was receiving from around the globe. 

I highly recommend anyone who’s interested in taking a deep dive into Azure/cloud security to give this basic project a go, as it certainly achieves every goal listed by the Project Scope stated at the beginning of this article. This also goes to show how customizable and efficient Azure can be when configured correctly. 

Source: https://www.linkedin.com/pulse/creating-honeypot-microsoft-azure-tutorial-gustavo-gradilla-vcv7c/

PowerShell script developer: https://github.com/joshmadakor1
