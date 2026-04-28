ls -la
cd /var/www/html
git status
git pull origin main
sudo systemctl restart nginx
sudo systemctl status nginx
df -h
free -m
top
ps aux | grep nginx
aws s3 ls
aws s3 ls s3://company-prod-backups
aws s3 cp /var/www/html/backup.tar.gz s3://company-prod-backups/
aws ec2 describe-instances --region us-east-1
kubectl get pods -n production
kubectl get services -n production
kubectl describe pod api-deployment-7d4b9c5f6-xk2pz -n production
docker ps
docker images
docker-compose up -d
mysql -u admin -pSup3rS3cr3t! -h 10.0.1.5 production
cat /etc/mysql/my.cnf
tail -f /var/log/nginx/access.log
tail -f /var/log/auth.log
ssh root@10.0.1.10
scp admin@10.0.1.20:/home/admin/.aws/credentials /tmp/
cat ~/.aws/credentials
vim ~/.aws/credentials
sudo crontab -l
ls /opt/app/
cd /opt/app && npm run build
git log --oneline -20
history
