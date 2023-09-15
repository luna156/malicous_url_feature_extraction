# Feature Engineering Refactoring
# 일괄 처리를 위한 함수화
def fd_length(parsedpath):
  try: 
    tmp = parsedpath.split('/')[1] 
  except: 
    tmp = None
  return tmp


def feature_extract(urldata):
  #Famous Domain check
  
  #alexa_10k = pd.read_csv(colab_path + 'cloudflare-radar-domains-top-100000-20230821-20230828.csv')
  #alexa_10k_list = []

  #for i in alexa_10k.index.values:
  #  alexa_10k_list.append(alexa_10k['domain'][i])

  url = urldata['url'].apply(lambda i: i if i[0:4] =='http' else "//" + i)
  parsed = url.apply(lambda i: urlparse(i))
  tld = url.apply(lambda i: get_tld(i,fail_silently=True)) 

  urldata['scheme'] = parsed.apply(lambda i: i.scheme) 
  urldata['netloc'] = parsed.apply(lambda i: i.netloc) 
  urldata['params'] = parsed.apply(lambda i: i.params) 
  urldata['query'] = parsed.apply(lambda i: i.query) 
  urldata['fragment'] = parsed.apply(lambda i: i.fragment) 
  urldata['tld'] = tld
  # Length Feature
  #Length of URL
  urldata['url_length'] = urldata['url'].apply(lambda i: len(i))

  #Hostname Length
  urldata['hostname_length'] = parsed.apply(lambda i: len(i.netloc)) 

  #Path Length
  urldata['path_length'] = parsed.apply(lambda i: len(i.path)) 

  #First Directory Length
  urldata['fd_length'] = parsed.apply(lambda i: fd_length(i.path))
  #Length of Top Level Domain
  urldata['tld_length'] = tld.apply(lambda i: len(i) if i is not None else None )

  #Count Feature
  #특수문자
  special_symbols = ['-', '@', '?', '%', '.', '=', 'http', 'https', 'www', '/', '//']
  for letter in special_symbols:
    urldata['count '+letter] = urldata['url'].apply(lambda i: i.count(letter))
  #숫자
  def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits
  urldata['count-digits']= urldata['url'].apply(lambda i: digit_count(i))
  #알파벳
  def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters
  urldata['count-letters']= urldata['url'].apply(lambda i: letter_count(i))

  # path부분의 /
  urldata['count_dir'] = parsed.apply(lambda i: i.path.count('/'))

  
#Use of IP or not in domain
  def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match: # 존재
        # print match.group()
        return 1
    else: # 없음
        # print 'No matching pattern found'
        return -1
  urldata['use_of_ip'] = urldata['url'].apply(lambda i: having_ip_address(i))

  #short link
  def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match: # 존재
        return 1
    else: # 없음
        return -1
  urldata['short_url'] = urldata['url'].apply(lambda i: shortening_service(i))


  #URL 속에 파일 확장자가 들어있는가?
  #파일 확장자가 들어있으면 1 , 없으면 -1
  def url_has_file(url):
    match = re.search('\.exe|\.zip|\.reg|\.rar|\.js|\.java|\.lib|\.log|\.bat|\.cmd|\.vbs|\.lnk|\.php|\.html|\.htm|\.hwp|\.hwpx|\.pptx|\.docx|\.iso|\.xls|\.xlsx',url)
    if match:
      return 1
    else:
      return -1
  urldata['url_has_file'] = urldata['url'].apply(lambda i: url_has_file(i))

  # URL 속에 Email 주소가 들어있는가?
  # 있으면 1, 없으면 -1
  def url_has_email(url):
    match = re.search('\w+\@\w+\.\w+' , url)
    if match:
      return 1
    else:
      return -1
  urldata['url_has_email'] = urldata['url'].apply(lambda i: url_has_email(i))


  #도메인과 URL의 길이 비율
  urldata['len_Domain_ratio'] = parsed.apply(lambda i: len(i.netloc)) / urldata['url_length']
  #Path와 URL의 길이 비율
  urldata['len_Path_ratio'] = parsed.apply(lambda i: len(i.path)) / urldata['url_length']
  #파라미터와 URL의 길이 비율
  urldata['len_Params_ratio'] =  parsed.apply(lambda i: len(i.params)) / urldata['url_length']
  #Query와 URL의 길이 비율
  urldata['len_Query_ratio'] =  parsed.apply(lambda i: len(i.query)) / urldata['url_length']
  #fragment와 URL의 길이 비율
  urldata['len_Fragment_ratio'] =  parsed.apply(lambda i: len(i.fragment)) / urldata['url_length']

  #의심 단어
  def suspicious_word(url):
    a = re.findall('confirm|account|secure|websc|login|signin|submit|update|logon|secure|wp|cmd|admin|ebayisapi', url)
    return len(a)
  urldata['suspicious_word'] = urldata['url'].apply(lambda i: suspicious_word(i))


  #Famous Domain check
  #alexa_10k = pd.read_csv(colab_path + 'cloudflare-radar-domains-top-100000-20230821-20230828.csv')
  #alexa_10k_list = []

  #for i in alexa_10k.index.values:
  #  alexa_10k_list.append(alexa_10k['domain'][i])

  #def dom_alexa_rank(url):
  #  ext = tldextract.extract(url)
  #  domain = ext.domain + '.' + ext.suffix 
  #  if domain in alexa_10k_list:
  #    return 1
  #  else:
  #    return -1
  #urldata['dom_alexa_rank'] = urldata['url'].apply(lambda i: dom_alexa_rank(i))

  #check protocol
  def https(scheme):
    if scheme == 'https':
      return 1
    return 0
  urldata['use_https'] = parsed.apply(lambda i: https(i.scheme))
  
  def http(scheme):
    if scheme == 'http':
      return 1
    return 0
  urldata['use_http'] = parsed.apply(lambda i: http(i.scheme))
  
  #검색량
  #def search_url_amount(url):
    #Daum_url='https://search.daum.net/search?w=tot&DA=YZR&t_nil_searchbox=btn&sug=&sugo=&sg=&o=&q='
    #strOri='&sm=tab_org&qvt=0'
    #response = requests.get(Daum_url + url +strOri)
    #getlen=len(response.text)
    #return getlen
  #urldata['search_url_amount'] = urldata['url'].apply(lambda i: search_url_amount(i))
  # 검색량 부분을 추가하니 5시간 돌려도 안끝나서 일단 주석처리
  return urldata