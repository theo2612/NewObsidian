Cron - crontab  
process started on boot  
responsible for facilitating and managing cronjobs  
crontab - a special file with formatting that is recognized by the cron process to execute each line step-by-step. They require 6 specific value  
min - what minute to execute at  
hour - what hour to execute at  
dom - what day of the month to execute at  
mon - what month of the year to execute at  
dow - what day of the week to execute at  
cmd - what command to execute  
0 *12 * * * cp -R /home/cmnatic/Documents /var/backups  
#backup “cmnatic”'s “Documents” every 12 hours  
* - wildcard for crontabs. If we don't wish to provide a value for a field or don't care what month, day, year it is execute... only that it is executed 12 hrs - use an *  
Resources  
Crontab generator [https://crontab-generator.org/](https://crontab-generator.org/)  
Cron Guru [https://crontab.guru/](https://crontab.guru/)  
$ crontab -e  
#use to edit Crontabs