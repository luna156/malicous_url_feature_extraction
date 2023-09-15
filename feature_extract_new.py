# Feature Engineering Refactoring
# 일괄 처리를 위한 함수화
def feature_extract(urldata):
  #Famous Domain check
  
  #alexa_10k = pd.read_csv(colab_path + 'cloudflare-radar-domains-top-100000-20230821-20230828.csv')
  #alexa_10k_list = []

  #for i in alexa_10k.index.values:
  #  alexa_10k_list.append(alexa_10k['domain'][i])
  
  urldata['scheme'] = np.NaN
  urldata['netloc'] = np.NaN
  urldata['params'] = np.NaN
  urldata['query'] = np.NaN
  urldata['fragment'] = np.NaN
  urldata['tld'] = np.NaN
  urldata['url_length'] = np.NaN
  urldata['hostname_length'] = np.NaN
  urldata['path_length'] = np.NaN
  urldata['fd_length'] = np.NaN
  urldata['tld_length'] = np.NaN

  special_symbols = ['-', '@', '?', '%', '.', '=', 'http', 'https', 'www', '/', '//']
  for letter in special_symbols:
    urldata['count '+letter]= np.NaN

  urldata['count-digits'] = np.NaN
  urldata['count-letters'] = np.NaN
  urldata['count_dir'] = np.NaN
  urldata['use_of_ip'] = np.NaN
  urldata['short_url'] = np.NaN
  urldata['url_has_file'] = np.NaN
  urldata['url_has_email'] = np.NaN
  #도메인과 URL의 길이 비율
  urldata['len_Domain_ratio'] = np.NaN
  #Path와 URL의 길이 비율
  urldata['len_Path_ratio'] = np.NaN
  #파라미터와 URL의 길이 비율
  urldata['len_Params_ratio'] = np.NaN
  #Query와 URL의 길이 비율
  urldata['len_Query_ratio'] = np.NaN
  #fragment와 URL의 길이 비율
  urldata['len_Fragment_ratio'] = np.NaN
  urldata['suspicious_word'] = np.NaN
  #alexa doamin check
  #urldata['dom_alexa_rank'] = np.NaN

  #check protocol
  urldata['use_https'] = np.NaN
  urldata['use_http'] = np.NaN

  #검색량
  #urldata['search_url_amount'] = np.NaN

  for i in range(len(urldata)):
    original = urldata['url'][i]
    url = original if original[0:4] =='http' else "//" + original
    parsed = urlparse(url)
    tld = get_tld(url,fail_silently=True)

    urldata['scheme'][i] = parsed.scheme
    urldata['netloc'][i] = parsed.netloc
    urldata['params'][i] = parsed.params
    urldata['query'][i] = parsed.query
    urldata['fragment'][i] = parsed.fragment
    urldata['tld'][i] = tld

    # Length Feature
    #Length of URL
    urldata['url_length'][i] = len(original)

    #Hostname Length
    urldata['hostname_length'][i] = len(parsed.netloc)

    #Path Length
    urldata['path_length'][i] = len(parsed.path)

    #First Directory Length
    try: 
      tmp = parsed.path.split('/')[1] 
    except: 
      tmp = None
    urldata['fd_length'][i] =  tmp

    #Length of Top Level Domain
    urldata['tld_length'][i] = len(tld) if tld is not None else None

    #Count Feature
    #특수문자
    for letter in special_symbols:
      urldata['count '+letter][i] = original.count(letter)

    #숫자,alpha, / count
    numcount = 0
    alphacount = 0
    dircount = 0;
    for t in  original:
      if t.isnumeric():
        numcount+=1
      if t.isalpha():
        alphacount+=1
      if t == '/':
        dircount+=1
    urldata['count-digits'][i] = numcount
    urldata['count-letters'][i] = alphacount
    urldata['count_dir'][i] = dircount

    #Use of IP or not in domain
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', original)
    if match: # 존재
      urldata['use_of_ip'][i] = 1
    else: # 없음
      urldata['use_of_ip'][i] = -1

    #short link
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      original)
    if match: # 존재
      urldata['short_url'][i] = 1
    else: # 없음
      urldata['short_url'][i] = -1 
    
    #URL 속에 파일 확장자가 들어있는가?
    match = re.search('\.exe|\.zip|\.reg|\.rar|\.js|\.java|\.lib|\.log|\.bat|\.cmd|\.vbs|\.lnk|\.php|\.html|\.htm|\.hwp|\.hwpx|\.pptx|\.docx|\.iso|\.xls|\.xlsx',url)
    if match: # 존재
      urldata['url_has_file'][i] = 1
    else: # 없음
      urldata['url_has_file'][i] = -1 

    # URL 속에 Email 주소가 들어있는가?
    match = re.search('\w+\@\w+\.\w+' , url)
    if match: # 존재
      urldata['url_has_email'][i] = 1
    else: # 없음
      urldata['url_has_email'][i] = -1 

    #도메인과 URL의 길이 비율
    urldata['len_Domain_ratio'][i] = len(parsed.netloc) / urldata['url_length'][i]
    #Path와 URL의 길이 비율
    urldata['len_Path_ratio'][i] = len(parsed.path) / urldata['url_length'][i]
    #파라미터와 URL의 길이 비율
    urldata['len_Params_ratio'][i] = len(parsed.params) / urldata['url_length'][i]
    #Query와 URL의 길이 비율
    urldata['len_Query_ratio'][i] = len(parsed.query) / urldata['url_length'][i]
    #fragment와 URL의 길이 비율
    urldata['len_Fragment_ratio'][i] = len(parsed.fragment) / urldata['url_length'][i]

    #의심 단어
    urldata['suspicious_word'][i] = len(re.findall('confirm|account|secure|websc|login|signin|submit|update|logon|secure|wp|cmd|admin|ebayisapi', url))

    #alexa doamin check
    #if parsed.netloc in alexa_10k_list:
    #  urldata['dom_alexa_rank'][i] =  1
    #else:
    #  urldata['dom_alexa_rank'][i] = -1

    #check protocol
    if original[0:5] == 'https':
      urldata['use_https'][i] = 1
    else: 
      urldata['use_https'][i] = -1

    if  original[0:4] == 'http' and original[0:5] != 'https':
      urldata['use_http'][i] = 1
    else: 
      urldata['use_http'][i] = -1

    #검색량
    #Daum_url='https://search.daum.net/search?w=tot&DA=YZR&t_nil_searchbox=btn&sug=&sugo=&sg=&o=&q='
    #strOri='&sm=tab_org&qvt=0'
    #response = requests.get(Daum_url + original +strOri)

    #urldata['search_url_amount'][i] = len(response.text)
    # 검색량 부분을 추가하니 5시간 돌려도 안끝나서 일단 주석처리

  return urldata