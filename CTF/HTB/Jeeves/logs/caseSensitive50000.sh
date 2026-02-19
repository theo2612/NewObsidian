for path in "askjeeves" "AskJeeves" "Jeeves" "jeeves" "ask"; do                           
  echo "Testing: /$path"                                                                  
  curl -s -o /dev/null -w "  Status: %{http_code}\n" "http://10.129.228.112:50000/$path"  
done 
