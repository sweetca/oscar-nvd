// CVE = Common Vulnerabilities and Exposures
// NVD = National Vulnerability Database
package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/codescoop/oscar-nvd/client"
	"github.com/codescoop/oscar-nvd/models"
	"github.com/codescoop/oscar-nvd/mongodata"
	"github.com/codescoop/oscar-nvd/times"
	log "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
	"strconv"
	"strings"
	"sync"
	"time"
	"github.com/codescoop/oscar-nvd/util"
)

const (
	CVEItems        = "CVE_Items"
	CVE             = "cve"
	CVEDataMeta     = "CVE_data_meta"
	CVEID           = "ID"
	LastModified    = "lastModifiedDate"
	PublishedDate   = "publishedDate"
	Configurations  = "configurations"
	Nodes           = "nodes"
	CpeMatch        = "cpe_match"
	Cpe23Uri        = "cpe23Uri"
	Affects         = "affects"
	Vendor          = "vendor"
	VendorData      = "vendor_data"
	VendorName      = "vendor_name"
	Product         = "product"
	ProductData     = "product_data"
	ProductName     = "product_name"
	References      = "references"
	ReferencesData  = "reference_data"
	ProblemType     = "problemtype"
	ProblemTypeData = "problemtype_data"
	Description     = "description"
	Value           = "value"
	Impact          = "impact"
	MetricV2        = "baseMetricV2"
	MetricV3        = "baseMetricV3"
	CvssV2          = "cvssV2"
	CvssV3          = "cvssV3"
	BaseScore       = "baseScore"
	Url             = "url"
	GitHub          = "github.com"
	GitLab          = "gitlab.com"
)

func Run() bool {
	job := util.FetchJob()
	if job == nil {
		return false
	}
	log.Warn("GitHubRelease job started")

	ctx := context.Background()
	mongoClient := mongodata.InitClient(ctx)

	start := client.FirstYear
	end := time.Now().Year()
	years := make([]string, 0)

	for start <= end {
		y := strconv.Itoa(start)
		years = append(years, y)
		start++
	}

	categories := getCategories()

	var syncProcess sync.WaitGroup
	for _, date := range years {
		syncProcess.Add(1)
		fetchYear(date, &syncProcess, mongoClient, categories, ctx)
	}
	syncProcess.Wait()

	syncProcess.Add(2)
	fetchYear(client.Recent, &syncProcess, mongoClient, categories, ctx)
	fetchYear(client.Modidified, &syncProcess, mongoClient, categories, ctx)
	syncProcess.Wait()

	util.FinishJob(job)
	log.Infof("done fetching NVD database")
	return true
}

func fetchYear(date string, syncProcess *sync.WaitGroup, mongoClient *mongo.Client, categories map[string]models.CVECategory, ctx context.Context) {
	log.Infof("start parse %v", date)

	nvdClient := client.New()
	cveFeed := nvdClient.FetchCVEFeed(date)
	cveItems := cveFeed[CVEItems].([]interface{})

	update := make([]models.CVE, 0)
	for _, cveItem := range cveItems {
		cveItem, ok := cveItem.(map[string]interface{})
		if !ok {
			continue
		}
		meta := fetchMeta(cveItem, categories)

		cve := cveItem[CVE].(map[string]interface{})
		cveDataMeta := cve[CVEDataMeta].(map[string]interface{})
		cveId := cveDataMeta[CVEID].(string)

		cveEntity := models.CVE{Id: cveId, Data: cveItem}
		if meta != nil {
			cveEntity.Meta = meta
		}
		update = append(update, cveEntity)
	}

	mongodata.WriteCVE(mongoClient, ctx, update)

	log.Infof("done parse %v", date)
	syncProcess.Done()
}

func fetchMeta(cveItem map[string]interface{}, categories map[string]models.CVECategory) *models.CVEMeta {
	meta := models.CVEMeta{}

	cpeMeta := make(map[string]string)
	affectsMeta := make(map[string]string)
	refMeta := make(map[string]string)
	catMeta := make([]models.CVECategory, 0)

	cve := cveItem[CVE]
	if cve != nil {
		cve := cve.(map[string]interface{})
		affects := cve[Affects]
		if affects != nil {
			affects := affects.(map[string]interface{})
			vendor := affects[Vendor]
			if vendor != nil {
				vendor := vendor.(map[string]interface{})
				vendorData := vendor[VendorData]
				if vendorData != nil {
					vendorData := vendorData.([]interface{})
					for _, vd := range vendorData {
						item, ok := vd.(map[string]interface{})
						if !ok {
							continue
						}
						vName := item[VendorName]
						vName = vName.(string)
						product := item[Product].(map[string]interface{})
						productData := product[ProductData].([]interface{})
						for _, pD := range productData {
							item, ok := pD.(map[string]interface{})
							if !ok {
								continue
							}
							pName := item[ProductName]
							pName = pName.(string)

							name := strings.ToLower(fmt.Sprintf("%s:%s", vName, pName))
							affectsMeta[name] = name
						}
					}
				}
			}
		}

		references := cve[References]
		if references != nil {
			references := references.(map[string]interface{})
			referencesData := references[ReferencesData]
			if referencesData != nil {
				referencesData := referencesData.([]interface{})
				for _, rfD := range referencesData {
					rf, ok := rfD.(map[string]interface{})
					if !ok {
						continue
					}
					rfItem := rf[Url]
					if rfItem != nil {
						rfItem := rfItem.(string)
						rfItem = strings.Replace(rfItem, "https://", "", 1)
						rfItem = strings.Replace(rfItem, "http://", "", 1)
						rfItem = strings.Replace(rfItem, "ftp://", "", 1)
						rfItem = strings.Replace(rfItem, "www.", "", 1)
						rfItem = strings.Replace(rfItem, "www1.", "", 1)
						rfItem = strings.Replace(rfItem, "www2.", "", 1)

						if strings.HasPrefix(rfItem, GitHub) {
							rfItem = strings.Replace(rfItem, GitHub+"/", "", 1)
							gitData := strings.Split(rfItem, "/")
							if len(gitData) == 1 {
								gitUrl := strings.ToLower(fmt.Sprintf("%s/%s", GitHub, gitData[0]))
								refMeta[gitUrl] = gitUrl
							} else {
								gitUrl := strings.ToLower(fmt.Sprintf("%s/%s/%s", GitHub, gitData[0], gitData[1]))
								refMeta[gitUrl] = gitUrl
							}
						} else if strings.HasPrefix(rfItem, GitLab) {
							rfItem = strings.Replace(rfItem, GitLab+"/", "", 1)
							gitData := strings.Split(rfItem, "/")
							if len(gitData) == 1 {
								gitUrl := strings.ToLower(fmt.Sprintf("%s/%s", GitLab, gitData[0]))
								refMeta[gitUrl] = gitUrl
							} else {
								gitUrl := strings.ToLower(fmt.Sprintf("%s/%s/%s", GitLab, gitData[0], gitData[1]))
								refMeta[gitUrl] = gitUrl
							}
						} else {
							rfItemArr := strings.Split(rfItem, "/")
							ref := strings.ToLower(rfItemArr[0])
							refMeta[ref] = ref
						}
					}
				}
			}
		}

		problemType := cve[ProblemType]
		if problemType != nil {
			problemType := problemType.(map[string]interface{})
			problemTypeData := problemType[ProblemTypeData]
			if problemTypeData != nil {
				problemTypeData := problemTypeData.([]interface{})
				for _, pbtD := range problemTypeData {
					pbt, ok := pbtD.(map[string]interface{})
					if !ok {
						continue
					}

					description := pbt[Description]
					if description != nil {
						description := description.([]interface{})
						for _, d := range description {
							dPbt, ok := d.(map[string]interface{})
							if !ok {
								continue
							}
							pbtVal := dPbt[Value]
							pbtValStr := pbtVal.(string)
							cat := categories[pbtValStr]
							if cat.Name != "" {
								catMeta = append(catMeta, cat)
							}
						}
					}
				}
			}
		}
	}

	configs := cveItem[Configurations]
	if configs != nil {
		configs := configs.(map[string]interface{})
		if configs != nil {
			nodes := configs[Nodes]
			if nodes != nil {
				nodes := nodes.([]interface{})
				for _, node := range nodes {
					n, ok := node.(map[string]interface{})
					if !ok {
						continue
					}
					cpeMatchArr := n[CpeMatch]
					if cpeMatchArr != nil {
						cpeMatchArr := cpeMatchArr.([]interface{})
						for _, cpeMatch := range cpeMatchArr {
							cpe, ok := cpeMatch.(map[string]interface{})
							if !ok {
								continue
							}

							uri := cpe[Cpe23Uri]
							uriStr := uri.(string)
							uriStr = strings.Replace(uriStr, "cpe:2.3", "", 1)
							uriStr = strings.Replace(uriStr, ":o:", "", 1)
							uriStr = strings.Replace(uriStr, ":a:", "", 1)
							uriStr = strings.Replace(uriStr, ":h:", "", 1)
							uriStr = strings.Replace(uriStr, ":*:*:*:*:*:*:*", "", 1)
							uriStrArr := strings.Split(uriStr, ":")

							cp := strings.ToLower(fmt.Sprintf("%s:%s", uriStrArr[0], uriStrArr[1]))
							cpeMeta[cp] = cp
						}
					}
				}
			}
		}
	}

	impact := cveItem[Impact]
	if impact != nil {
		impact := impact.(map[string]interface{})
		metric := impact[MetricV3]
		if metric != nil {
			metric := metric.(map[string]interface{})
			cvs := metric[CvssV3].(map[string]interface{})
			score := cvs[BaseScore].(float64)
			meta.Severity = score
		} else {
			metric = impact[MetricV2]
			if metric != nil {
				metric := metric.(map[string]interface{})
				cvs := metric[CvssV2].(map[string]interface{})
				score := cvs[BaseScore].(float64)
				meta.Severity = score
			} else {
				meta.Severity = -1.0
			}
		}
	}

	published := cveItem[PublishedDate]
	publishedStr := published.(string)
	meta.Published = fetchTimestamp(publishedStr)

	lastMod := cveItem[LastModified]
	lastModStr := lastMod.(string)
	meta.Modified = fetchTimestamp(lastModStr)

	meta.Cpe = make([]string, 0)
	for k := range cpeMeta {
		meta.Cpe = append(meta.Cpe, k)
	}

	meta.Affects = make([]string, 0)
	for k := range affectsMeta {
		meta.Affects = append(meta.Affects, k)
	}

	meta.Ref = make([]string, 0)
	for k := range refMeta {
		meta.Ref = append(meta.Ref, k)
	}

	meta.Categories = catMeta

	return &meta
}

func fetchTimestamp(date string) time.Time {
	// 1999-12-30T05:00Z
	date = strings.Split(date, "T")[0]
	return times.TimeFromString(date)
}

func getCategories() map[string]models.CVECategory {
	parsed := make([]models.CVECategory, 0)
	err := json.Unmarshal([]byte(jsonData), &parsed)
	if err != nil {
		log.Panicf("Error parsing cve categories : %v", err)
	}

	result := make(map[string]models.CVECategory)
	for _, c := range parsed {
		result[c.Name] = c
	}

	return result
}

var jsonData = "[{\"name\":\"CWE-824\",\"id\":\"Access of Uninitialized Pointer\",\"description\":\"The program accesses or uses a pointer that has not been initialized.\"},{\"name\":\"CWE-407\",\"id\":\"Algorithmic Complexity\",\"description\":\"An algorithm in a product has an inefficient worst-case computational complexity that may be detrimental to system performance and can be triggered by an attacker, typically using crafted manipulations that ensure that the worst case is being reached.\"},{\"name\":\"CWE-774\",\"id\":\"Allocation of File Descriptors or Handles Without Limits or Throttling\",\"description\":\"The software allocates file descriptors or handles on behalf of an actor without imposing any restrictions on how many descriptors can be allocated, in violation of the intended security policy for that actor.\"},{\"name\":\"CWE-88\",\"id\":\"Argument Injection or Modification\",\"description\":\"The software does not sufficiently delimit the arguments being passed to a component in another control sphere, allowing alternate arguments to be provided, leading to potentially security-relevant changes.\"},{\"name\":\"CWE-405\",\"id\":\"Asymmetric Resource Consumption (Amplification)\",\"description\":\"Software that does not appropriately monitor or control resource consumption can lead to adverse system performance.\"},{\"name\":\"CWE-287\",\"id\":\"Authentication Issues\",\"description\":\"When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct.\"},{\"name\":\"CWE-119\",\"id\":\"Buffer Errors\",\"description\":\"The software performs operations on a memory buffer, but it can read from or write to a memory location that is outside of the intended boundary of the buffer.\"},{\"name\":\"CWE-417\",\"id\":\"Channel and Path Errors\",\"description\":\"Weaknesses in this category are related to improper handling of communication channels and access paths.\"},{\"name\":\"CWE-171\",\"id\":\"Cleansing, Canonicalization, and Comparison Errors\",\"description\":\"Weaknesses in this category are related to improper handling of data within protection mechanisms that attempt to perform neutralization for untrusted data.\"},{\"name\":\"CWE-17\",\"id\":\"Code\",\"description\":\"Weaknesses in this category are typically introduced during code development, including specification, design, and implementation.\"},{\"name\":\"CWE-94\",\"id\":\"Code Injection\",\"description\":\"The software constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment.\"},{\"name\":\"CWE-77\",\"id\":\"Command Injection\",\"description\":\"The software constructs all or part of a command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended command when it is sent to a downstream component.\"},{\"name\":\"CWE-16\",\"id\":\"Configuration\",\"description\":\"Weaknesses in this category are typically introduced during the configuration of the software.\"},{\"name\":\"CWE-216\",\"id\":\"Containment Errors (Container Errors)\",\"description\":\"This tries to cover various problems in which improper data are included within a container.\"},{\"name\":\"CWE-255\",\"id\":\"Credentials Management\",\"description\":\"Weaknesses in this category are related to the management of credentials.\"},{\"name\":\"CWE-352\",\"id\":\"Cross-Site Request Forgery (CSRF)\",\"description\":\"The web application does not, or can not, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request.\"},{\"name\":\"CWE-79\",\"id\":\"Cross-Site Scripting (XSS)\",\"description\":\"The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.\"},{\"name\":\"CWE-310\",\"id\":\"Cryptographic Issues\",\"description\":\"Weaknesses in this category are related to the use of cryptography.\"},{\"name\":\"CWE-19\",\"id\":\"Data Handling\",\"description\":\"Weaknesses in this category are typically found in functionality that processes data.\"},{\"name\":\"CWE-502\",\"id\":\"Deserialization of Untrusted Data\",\"description\":\"The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.\"},{\"name\":\"CWE-369\",\"id\":\"Divide By Zero\",\"description\":\"The product divides a value by zero.\"},{\"name\":\"CWE-415\",\"id\":\"Double Free\",\"description\":\"The product calls free() twice on the same memory address, potentially leading to modification of unexpected memory locations.\"},{\"name\":\"CWE-172\",\"id\":\"Encoding Error\",\"description\":\"The software does not properly encode or decode the data, resulting in unexpected values.\"},{\"name\":\"CWE-2\",\"id\":\"Environment\",\"description\":\"Weaknesses in this category are typically introduced during unexpected environmental conditions.\"},{\"name\":\"CWE-388\",\"id\":\"Error Handling\",\"description\":\"This category includes weaknesses that occur when an application does not properly handle errors that occur during processing.\"},{\"name\":\"CWE-749\",\"id\":\"Exposed Dangerous Method or Function\",\"description\":\"The software provides an Applications Programming Interface (API) or similar interface for interaction with external actors, but the interface includes a dangerous method or function that is not properly restricted.\"},{\"name\":\"CWE-668\",\"id\":\"Exposure of Resource to Wrong Sphere\",\"description\":\"The product exposes a resource to the wrong control sphere, providing unintended actors with inappropriate access to the resource.\"},{\"name\":\"CWE-472\",\"id\":\"External Control of Assumed-Immutable Web Parameter\",\"description\":\"The web application does not sufficiently verify inputs that are assumed to be immutable but are actually externally controllable, such as hidden form fields.\"},{\"name\":\"CWE-642\",\"id\":\"External Control of Critical State Data\",\"description\":\"The software stores security-critical state information about its users, or the software itself, in a location that is accessible to unauthorized actors.\"},{\"name\":\"CWE-610\",\"id\":\"Externally Controlled Reference to a Resource in Another Sphere\",\"description\":\"The product uses an externally controlled name or reference that resolves to a resource that is outside of the intended control sphere.\"},{\"name\":\"CWE-538\",\"id\":\"File and Directory Information Exposure\",\"description\":\"The product stores sensitive information in files or directories that are accessible to actors outside of the intended control sphere.\"},{\"name\":\"CWE-769\",\"id\":\"File Descriptor Exhaustion\",\"description\":\"The software can be influenced by an attacker to open more files than are supported by the system.\"},{\"name\":\"CWE-552\",\"id\":\"Files or Directories Accessible to External Parties\",\"description\":\"Files or directories are accessible in the environment that should not be.\"},{\"name\":\"CWE-134\",\"id\":\"Format String Vulnerability\",\"description\":\"The software uses a function that accepts a format string as an argument, but the format string originates from an external source.\"},{\"name\":\"CWE-284\",\"id\":\"Improper Access Control\",\"description\":\"The software does not restrict or incorrectly restricts access to a resource from an unauthorized actor.\"},{\"name\":\"CWE-118\",\"id\":\"Improper Access of Indexable Resource ('Range Error')\",\"description\":\"The software does not restrict or incorrectly restricts operations within the boundaries of a resource that is accessed using an index or pointer, such as memory or files.\"},{\"name\":\"CWE-285\",\"id\":\"Improper Authorization\",\"description\":\"The software does not perform or incorrectly performs an authorization check when an actor attempts to access a resource or perform an action.\"},{\"name\":\"CWE-295\",\"id\":\"Improper Certificate Validation\",\"description\":\"The software does not validate, or incorrectly validates, a certificate.\"},{\"name\":\"CWE-754\",\"id\":\"Improper Check for Unusual or Exceptional Conditions\",\"description\":\"The software does not check or improperly checks for unusual or exceptional conditions that are not expected to occur frequently during day to day operation of the software.\"},{\"name\":\"CWE-664\",\"id\":\"Improper Control of a Resource Through its Lifetime\",\"description\":\"The software does not maintain or incorrectly maintains control over a resource throughout its lifetime of creation, use, and release.\"},{\"name\":\"CWE-913\",\"id\":\"Improper Control of Dynamically-Managed Code Resources\",\"description\":\"The software does not properly restrict reading from or writing to dynamically-managed code resources such as variables, objects, classes, attributes, functions, or executable instructions or statements.\"},{\"name\":\"CWE-99\",\"id\":\"Improper Control of Resource Identifiers ('Resource Injection')\",\"description\":\"The software receives input from an upstream component, but it does not restrict or incorrectly restricts the input before it is used as an identifier for a resource that may be outside the intended sphere of control.\"},{\"name\":\"CWE-116\",\"id\":\"Improper Encoding or Escaping of Output\",\"description\":\"The software prepares a structured message for communication with another component, but encoding or escaping of the data is either missing or done incorrectly. As a result, the intended structure of the message is not preserved.\"},{\"name\":\"CWE-707\",\"id\":\"Improper Enforcement of Message or Data Structure\",\"description\":\"The software does not enforce or incorrectly enforces that structured messages or data are well-formed before being read from an upstream component or sent to a downstream component.\"},{\"name\":\"CWE-665\",\"id\":\"Improper Initialization\",\"description\":\"The software does not initialize or incorrectly initializes a resource, which might leave the resource in an unexpected state when it is accessed or used.\"},{\"name\":\"CWE-93\",\"id\":\"Improper Neutralization of CRLF Sequences ('CRLF Injection')\",\"description\":\"The software uses CRLF (carriage return line feeds) as a special element, e.g. to separate lines or records, but it does not neutralize or incorrectly neutralizes CRLF sequences from inputs.\"},{\"name\":\"CWE-113\",\"id\":\"Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')\",\"description\":\"The software receives data from an upstream component, but does not neutralize or incorrectly neutralizes CR and LF characters before the data is included in outgoing HTTP headers.\"},{\"name\":\"CWE-943\",\"id\":\"Improper Neutralization of Special Elements in Data Query Logic\",\"description\":\"The application generates a query intended to access or manipulate data in a data store such as a database, but it does not neutralize or incorrectly neutralizes special elements that can modify the intended logic of the query.\"},{\"name\":\"CWE-90\",\"id\":\"Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')\",\"description\":\"The software constructs all or part of an LDAP query using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended LDAP query when it is sent to a downstream component.\"},{\"name\":\"CWE-404\",\"id\":\"Improper Resource Shutdown or Release\",\"description\":\"The program does not release or incorrectly releases a resource before it is made available for re-use.\"},{\"name\":\"CWE-611\",\"id\":\"Improper Restriction of XML External Entity Reference ('XXE')\",\"description\":\"The software processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control, causing the product to embed incorrect documents into its output.\"},{\"name\":\"CWE-129\",\"id\":\"Improper Validation of Array Index\",\"description\":\"The product uses untrusted input when calculating or using an array index, but the product does not validate or incorrectly validates the index to ensure the index references a valid position within the array.\"},{\"name\":\"CWE-297\",\"id\":\"Improper Validation of Certificate with Host Mismatch\",\"description\":\"The software communicates with a host that provides a certificate, but the software does not properly ensure that the certificate is actually associated with that host.\"},{\"name\":\"CWE-347\",\"id\":\"Improper Verification of Cryptographic Signature\",\"description\":\"The software does not verify, or incorrectly verifies, the cryptographic signature for data.\"},{\"name\":\"CWE-358\",\"id\":\"Improperly Implemented Security Check for Standard\",\"description\":\"The software does not implement or incorrectly implements one or more security-relevant checks as specified by the design of a standardized algorithm, protocol, or technique.\"},{\"name\":\"CWE-326\",\"id\":\"Inadequate Encryption Strength\",\"description\":\"The software stores or transmits sensitive data using an encryption scheme that is theoretically sound, but is not strong enough for the level of protection required.\"},{\"name\":\"CWE-184\",\"id\":\"Incomplete Blacklist\",\"description\":\"An application uses a blacklist of prohibited values, but the blacklist is incomplete.\"},{\"name\":\"CWE-444\",\"id\":\"Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')\",\"description\":\"When malformed or abnormal HTTP requests are interpreted by one or more entities in the data flow between the user and the web server, such as a proxy or firewall, they can be interpreted inconsistently, allowing the attacker to smuggle a request to one device without the other device being aware of it.\"},{\"name\":\"CWE-682\",\"id\":\"Incorrect Calculation\",\"description\":\"The software performs a calculation that generates incorrect or unintended results that are later used in security-critical decisions or resource management.\"},{\"name\":\"CWE-185\",\"id\":\"Incorrect Regular Expression\",\"description\":\"The software specifies a regular expression in a way that causes data to be improperly matched or compared.\"},{\"name\":\"CWE-669\",\"id\":\"Incorrect Resource Transfer Between Spheres\",\"description\":\"The product does not properly transfer a resource/behavior to another sphere, or improperly imports a resource/behavior from another sphere, in a manner that provides unintended control over that resource.\"},{\"name\":\"CWE-704\",\"id\":\"Incorrect Type Conversion or Cast\",\"description\":\"The software does not correctly convert an object, resource or structure from one type to a different type.\"},{\"name\":\"CWE-398\",\"id\":\"Indicator of Poor Code Quality\",\"description\":\"The code has features that do not directly introduce a weakness or vulnerability, but indicate that the product has not been carefully developed or maintained.\"},{\"name\":\"CWE-534\",\"id\":\"Information Exposure Through Debug Log Files\",\"description\":\"The application does not sufficiently restrict access to a log file that is used for debugging.\"},{\"name\":\"CWE-532\",\"id\":\"Information Exposure Through Log Files\",\"description\":\"Information written to log files can be of a sensitive nature and give valuable guidance to an attacker or expose sensitive user information.\"},{\"name\":\"CWE-200\",\"id\":\"Information Leak / Disclosure\",\"description\":\"An information exposure is the intentional or unintentional disclosure of information to an actor that is not explicitly authorized to have access to that information.\"},{\"name\":\"CWE-199\",\"id\":\"Information Management Errors\",\"description\":\"Weaknesses in this category are related to improper handling of sensitive information.\"},{\"name\":\"CWE-74\",\"id\":\"Injection\",\"description\":\"The software constructs all or part of a command, data structure, or record using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify how it is parsed or interpreted when it is sent to a downstream component.\"},{\"name\":\"CWE-20\",\"id\":\"Input Validation\",\"description\":\"The product does not validate or incorrectly validates input that can affect the control flow or data flow of a program.\"},{\"name\":\"CWE-485\",\"id\":\"Insufficient Encapsulation\",\"description\":\"The product does not sufficiently encapsulate critical data or functionality.\"},{\"name\":\"CWE-331\",\"id\":\"Insufficient Entropy\",\"description\":\"The software uses an algorithm or scheme that produces insufficient entropy, leaving patterns or clusters of values that are more likely to occur than others.\"},{\"name\":\"CWE-332\",\"id\":\"Insufficient Entropy in PRNG\",\"description\":\"The lack of entropy available for, or used by, a Pseudo-Random Number Generator (PRNG) can be a stability and security threat.\"},{\"name\":\"NVD-CWE-noinfo\",\"id\":\"Insufficient Information\",\"description\":\"There is insufficient information about the issue to classify it; details are unkown or unspecified.\"},{\"name\":\"CWE-613\",\"id\":\"Insufficient Session Expiration\",\"description\":\"According to WASC, Insufficient Session Expiration is when a web site permits an attacker to reuse old session credentials or session IDs for authorization.\"},{\"name\":\"CWE-345\",\"id\":\"Insufficient Verification of Data Authenticity\",\"description\":\"The software does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.\"},{\"name\":\"CWE-190\",\"id\":\"Integer Overflow or Wraparound\",\"description\":\"The software performs a calculation that can produce an integer overflow or wraparound, when the logic assumes that the resulting value will always be larger than the original value. This can introduce other weaknesses when the calculation is used for resource management or execution control.\"},{\"name\":\"CWE-191\",\"id\":\"Integer Underflow (Wrap or Wraparound)\",\"description\":\"The product subtracts one value from another, such that the result is less than the minimum allowable integer value, which produces a value that is not equal to the correct result.\"},{\"name\":\"CWE-435\",\"id\":\"Interaction Error\",\"description\":\"An interaction error occurs when two entities work correctly when running independently, but they interact in unexpected ways when they are run together.\"},{\"name\":\"CWE-436\",\"id\":\"Interpretation Conflict\",\"description\":\"Product A handles inputs or steps differently than Product B, which causes A to perform incorrect actions based on its perception of B's state.\"},{\"name\":\"CWE-320\",\"id\":\"Key Management Errors\",\"description\":\"Weaknesses in this category are related to errors in the management of cryptographic keys.\"},{\"name\":\"CWE-59\",\"id\":\"Link Following\",\"description\":\"The software attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.\"},{\"name\":\"CWE-1\",\"id\":\"Location\",\"description\":\"Weaknesses in this category are organized based on which phase they are introduced during the software development and deployment process.\"},{\"name\":\"CWE-306\",\"id\":\"Missing Authentication for Critical Function\",\"description\":\"The software does not perform any authentication for functionality that requires a provable user identity or consumes a significant amount of resources.\"},{\"name\":\"CWE-775\",\"id\":\"Missing Release of File Descriptor or Handle after Effective Lifetime\",\"description\":\"The software does not release a file descriptor or handle after its effective lifetime has ended, i.e., after the file descriptor/handle is no longer needed.\"},{\"name\":\"CWE-471\",\"id\":\"Modification of Assumed-Immutable Data (MAID)\",\"description\":\"The software does not properly protect an assumed-immutable element from being modified by an attacker.\"},{\"name\":\"CWE-476\",\"id\":\"NULL Pointer Dereference\",\"description\":\"A NULL pointer dereference occurs when the application dereferences a pointer that it expects to be valid, but is NULL, typically causing a crash or exit.\"},{\"name\":\"CWE-189\",\"id\":\"Numeric Errors\",\"description\":\"Weaknesses in this category are related to improper calculation or conversion of numbers.\"},{\"name\":\"CWE-346\",\"id\":\"Origin Validation Error\",\"description\":\"The software does not properly verify that the source of data or communication is valid.\"},{\"name\":\"CWE-78\",\"id\":\"OS Command Injections\",\"description\":\"The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component.\"},{\"name\":\"NVD-CWE-Other\",\"id\":\"Other\",\"description\":\"NVD is only using a subset of CWE for mapping instead of the entire CWE, and the weakness type is not covered by that subset.\"},{\"name\":\"CWE-125\",\"id\":\"Out-of-bounds Read\",\"description\":\"The software reads data past the end, or before the beginning, of the intended buffer.\"},{\"name\":\"CWE-787\",\"id\":\"Out-of-bounds Write\",\"description\":\"The software writes data past the end, or before the beginning, of the intended buffer.\"},{\"name\":\"CWE-21\",\"id\":\"Path Equivalence\",\"description\":\"Weaknesses in this category can be used to access files outside of a restricted directory (path traversal) or to perform operations on files that would otherwise be restricted (path equivalence).\"},{\"name\":\"CWE-22\",\"id\":\"Path Traversal\",\"description\":\"The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory.\"},{\"name\":\"CWE-275\",\"id\":\"Permission Issues\",\"description\":\"Weaknesses in this category are related to improper assignment or handling of permissions.\"},{\"name\":\"CWE-264\",\"id\":\"Permissions, Privileges, and Access Control\",\"description\":\"Weaknesses in this category are related to the management of permissions, privileges, and other security features that are used to perform access control.\"},{\"name\":\"CWE-693\",\"id\":\"Protection Mechanism Failure\",\"description\":\"The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.\"},{\"name\":\"CWE-362\",\"id\":\"Race Conditions\",\"description\":\"The program contains a code sequence that can run concurrently with other code, and the code sequence requires temporary, exclusive access to a shared resource, but a timing window exists in which the shared resource can be modified by another code sequence that is operating concurrently.\"},{\"name\":\"CWE-137\",\"id\":\"Representation Errors\",\"description\":\"Weaknesses in this category are introduced when inserting or converting data from one representation into another.\"},{\"name\":\"CWE-399\",\"id\":\"Resource Management Errors\",\"description\":\"Weaknesses in this category are related to improper management of system resources.\"},{\"name\":\"CWE-254\",\"id\":\"Security Features\",\"description\":\"Software security is not security software. Here we're concerned with topics like authentication, access control, confidentiality, cryptography, and privilege management.\"},{\"name\":\"CWE-220\",\"id\":\"Sensitive Data Under FTP Root\",\"description\":\"The application stores sensitive data under the FTP document root with insufficient access control, which might make it accessible to untrusted parties.\"},{\"name\":\"CWE-918\",\"id\":\"Server-Side Request Forgery (SSRF)\",\"description\":\"The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.\"},{\"name\":\"CWE-384\",\"id\":\"Session Fixation\",\"description\":\"Authenticating a user, or otherwise establishing a new user session, without invalidating any existing session identifier gives an attacker the opportunity to steal authenticated sessions.\"},{\"name\":\"CWE-18\",\"id\":\"Source Code\",\"description\":\"Weaknesses in this category are typically found within source code.\"},{\"name\":\"CWE-89\",\"id\":\"SQL Injection\",\"description\":\"The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.\"},{\"name\":\"CWE-371\",\"id\":\"State Issues\",\"description\":\"Weaknesses in this category are related to improper management of system state.\"},{\"name\":\"CWE-361\",\"id\":\"Time and State\",\"description\":\"Weaknesses in this category are related to the improper management of time and state in an environment that supports simultaneous or near-simultaneous computation by multiple systems, processes, or threads.\"},{\"name\":\"CWE-400\",\"id\":\"Uncontrolled Resource Consumption ('Resource Exhaustion')\",\"description\":\"The software does not properly restrict the size or amount of resources that are requested or influenced by an actor, which can be used to consume more resources than intended.\"},{\"name\":\"CWE-427\",\"id\":\"Uncontrolled Search Path Element\",\"description\":\"The product uses a fixed or controlled search path to find resources, but one or more locations in that path can be under the control of unintended actors.\"},{\"name\":\"CWE-441\",\"id\":\"Unintended Proxy or Intermediary ('Confused Deputy')\",\"description\":\"The software receives a request, message, or directive from an upstream component, but the software does not sufficiently preserve the original source of the request before forwarding the request to an external actor that is outside of the software's control sphere. This causes the software to appear to be the source of the request, leading it to act as a proxy or other intermediary between the upstream component and the external actor.\"},{\"name\":\"CWE-428\",\"id\":\"Unquoted Search Path or Element\",\"description\":\"The product uses a search path that contains an unquoted element, in which the element contains whitespace or other separators. This can cause the product to access resources in a parent path.\"},{\"name\":\"CWE-434\",\"id\":\"Unrestricted Upload of File with Dangerous Type\",\"description\":\"The software allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.\"},{\"name\":\"CWE-426\",\"id\":\"Untrusted Search Path\",\"description\":\"The application searches for critical resources using an externally-supplied search path that can point to resources that are not under the application's direct control.\"},{\"name\":\"CWE-601\",\"id\":\"URL Redirection to Untrusted Site ('Open Redirect')\",\"description\":\"A web application accepts a user-controlled input that specifies a link to an external site, and uses that link in a Redirect. This simplifies phishing attacks.\"},{\"name\":\"CWE-416\",\"id\":\"Use After Free\",\"description\":\"Referencing memory after it has been freed can cause a program to crash, use unexpected values, or execute code.\"},{\"name\":\"CWE-327\",\"id\":\"Use of a Broken or Risky Cryptographic Algorithm\",\"description\":\"The use of a broken or risky cryptographic algorithm is an unnecessary risk that may result in the exposure of sensitive information.\"},{\"name\":\"CWE-338\",\"id\":\"Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)\",\"description\":\"The product uses a Pseudo-Random Number Generator (PRNG) in a security context, but the PRNG is not cryptographically strong.\"},{\"name\":\"CWE-798\",\"id\":\"Use of Hard-coded Credentials\",\"description\":\"The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data.\"},{\"name\":\"CWE-330\",\"id\":\"Use of Insufficiently Random Values\",\"description\":\"The software may use insufficiently random numbers or values in a security context that depends on unpredictable numbers.\"},{\"name\":\"CWE-694\",\"id\":\"Use of Multiple Resources with Duplicate Identifier\",\"description\":\"The software uses multiple resources that can have the same identifier, in a context in which unique identifiers are required.\"},{\"name\":\"CWE-640\",\"id\":\"Weak Password Recovery Mechanism for Forgotten Password\",\"description\":\"The software contains a mechanism for users to recover or change their passwords without knowing the original password, but the mechanism is weak.\"},{\"name\":\"CWE-123\",\"id\":\"Write-what-where Condition\",\"description\":\"Any condition where the attacker has the ability to write an arbitrary value to an arbitrary location, often as the result of a buffer overflow.\"},{\"name\":\"CWE-91\",\"id\":\"XML Injection (aka Blind XPath Injection)\",\"description\":\"The software does not properly neutralize special elements that are used in XML, allowing attackers to modify the syntax, content, or commands of the XML before it is processed by an end system.\"}]"
