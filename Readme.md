
###### POST /addScan
> github action stage make this call with backend
> INPUT
```json
{
  "project_name": "cve_test",
  "project_id": "cve_test_1",
  "scan_id": "scan_cve_test_1",
  "git_link": "https://github.com/test/cve",
  "scan_link": [
    "https://github.com/test/cve",
    "https://github.com/scan/cve"
  ],
  "cves": [
    {
      "category": "java",
      "solutions": [
        "solution 1",
        "solution 2"
      ],
      "severity": "high",
      "cve_id": "CVE-111",
      "description": "some description",
      "vulnerability": "vulnerability name"
    },
    {
      "category": "spring",
      "solutions": [
        "solution 10",
        "solution 0"
      ],
      "severity": "Moderatw",
      "cve_id": "CVE-101",
      "description": "some description",
      "vulnerability": "vulnerability name"
    }
  ],
  "pom_xml": "Cjxwcm9qZWN0IHhtbG5zPSJodHRwOi8vbWF2ZW4uYXBhY2hlLm9yZy9QT00vNC4wLjAiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTpzY2hlbWFMb2NhdGlvbj0iaHR0cDovL21hdmVuLmFwYWNoZS5vcmcvUE9NLzQuMC4wIGh0dHA6Ly9tYXZlbi5hcGFjaGUub3JnL3hzZC9tYXZlbi00LjAuMC54c2QiPgo8bW9kZWxWZXJzaW9uPjQuMC4wPC9tb2RlbFZlcnNpb24+Cjxncm91cElkPmttcy1hcGktZXhhbXBsZXM8L2dyb3VwSWQ+CjxhcnRpZmFjdElkPmttcy1hcGktZXhhbXBsZXM8L2FydGlmYWN0SWQ+Cjx2ZXJzaW9uPjAuMC4xLVNOQVBTSE9UPC92ZXJzaW9uPgo8ZGVwZW5kZW5jaWVzPgo8ZGVwZW5kZW5jeT4KPGdyb3VwSWQ+b3JnLmFwYWNoZS5odHRwY29tcG9uZW50czwvZ3JvdXBJZD4KPGFydGlmYWN0SWQ+aHR0cGNsaWVudDwvYXJ0aWZhY3RJZD4KPHZlcnNpb24+NC4zLjI8L3ZlcnNpb24+Cjx0eXBlPmphcjwvdHlwZT4KPHNjb3BlPmNvbXBpbGU8L3Njb3BlPgo8L2RlcGVuZGVuY3k+CjxkZXBlbmRlbmN5Pgo8Z3JvdXBJZD5vcmcuYXBhY2hlLmh0dHBjb21wb25lbnRzPC9ncm91cElkPgo8YXJ0aWZhY3RJZD5odHRwY2xpZW50LWNhY2hlPC9hcnRpZmFjdElkPgo8dmVyc2lvbj40LjMuMjwvdmVyc2lvbj4KPHR5cGU+amFyPC90eXBlPgo8c2NvcGU+Y29tcGlsZTwvc2NvcGU+CjwvZGVwZW5kZW5jeT4KPGRlcGVuZGVuY3k+Cjxncm91cElkPm9yZy5hcGFjaGUuaHR0cGNvbXBvbmVudHM8L2dyb3VwSWQ+CjxhcnRpZmFjdElkPmh0dHBtaW1lPC9hcnRpZmFjdElkPgo8dmVyc2lvbj40LjMuMjwvdmVyc2lvbj4KPHR5cGU+amFyPC90eXBlPgo8c2NvcGU+Y29tcGlsZTwvc2NvcGU+CjwvZGVwZW5kZW5jeT4KPGRlcGVuZGVuY3k+Cjxncm91cElkPmNvbS5mYXN0ZXJ4bWwuamFja3Nvbi5jb3JlPC9ncm91cElkPgo8YXJ0aWZhY3RJZD5qYWNrc29uLWNvcmU8L2FydGlmYWN0SWQ+Cjx2ZXJzaW9uPjIuNC4wPC92ZXJzaW9uPgo8L2RlcGVuZGVuY3k+CjxkZXBlbmRlbmN5Pgo8Z3JvdXBJZD5jb20uZmFzdGVyeG1sLmphY2tzb24uY29yZTwvZ3JvdXBJZD4KPGFydGlmYWN0SWQ+amFja3Nvbi1kYXRhYmluZDwvYXJ0aWZhY3RJZD4KPHZlcnNpb24+Mi40LjA8L3ZlcnNpb24+CjwvZGVwZW5kZW5jeT4KPC9kZXBlbmRlbmNpZXM+CjxidWlsZD4KPHBsdWdpbnM+CjxwbHVnaW4+CjxhcnRpZmFjdElkPm1hdmVuLWNvbXBpbGVyLXBsdWdpbjwvYXJ0aWZhY3RJZD4KPHZlcnNpb24+My41LjE8L3ZlcnNpb24+Cjxjb25maWd1cmF0aW9uPgo8c291cmNlPjEuNzwvc291cmNlPgo8dGFyZ2V0PjEuNzwvdGFyZ2V0Pgo8L2NvbmZpZ3VyYXRpb24+CjwvcGx1Z2luPgo8L3BsdWdpbnM+CjwvYnVpbGQ+CjwvcHJvamVjdD4K",
  "tags": [
    "string"
  ]
}
```



###### GET getLatestScan
```
curl -X 'GET' \
  'http://127.0.0.1:8000/getLatestScan/?project_id=cve_test_1' \
  -H 'accept: application/json'
```
>response
```json
{
  "projectName": "cve_test",
  "projectId": "cve_test_1",
  "scan_id": "scan_cve_test_1",
  "related_links": [
    "https://github.com/test/cve|https://github.com/scan/cve"
  ],
  "tags": [
    "string"
  ],
  "cves": [
    {
      "cve_id": "CVE-111",
      "severity": "high",
      "vulnerability": "vulnerability name",
      "description": "some description",
      "category": "java",
      "solutions": [
        "solution 1",
        "solution 2"
      ]
    },
    {
      "cve_id": "CVE-101",
      "severity": "Moderatw",
      "vulnerability": "vulnerability name",
      "description": "some description",
      "category": "spring",
      "solutions": [
        "solution 10",
        "solution 0"
      ]
    }
  ],
  "solution": null
}
```