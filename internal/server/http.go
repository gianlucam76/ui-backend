/*
Copyright 2024. projectsveltos.io. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/gin-gonic/gin"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"

	libsveltosv1beta1 "github.com/projectsveltos/libsveltos/api/v1beta1"
	logs "github.com/projectsveltos/libsveltos/lib/logsettings"
)

const (
	maxItems = 6
)

type Token struct {
	Value string `json:"token,omitempty"`
}

var (
	ginLogger logr.Logger

	getManagedCAPIClusters = func(c *gin.Context) {
		ginLogger.V(logs.LogDebug).Info("get managed ClusterAPI Clusters")

		limit, skip := getLimitAndSkipFromQuery(c)
		ginLogger.V(logs.LogDebug).Info(fmt.Sprintf("limit %d skip %d", limit, skip))
		filters, err := getClusterFiltersFromQuery(c)
		if err != nil {
			ginLogger.V(logs.LogInfo).Info(fmt.Sprintf("bad request %s: %v", c.Request.URL, err))
			_ = c.AbortWithError(http.StatusBadRequest, err)
			return
		}
		ginLogger.V(logs.LogDebug).Info(fmt.Sprintf("filters: namespace %q name %q labels %q",
			filters.Namespace, filters.name, filters.labelSelector))

		user, err := validateToken(c)
		if err != nil {
			_ = c.AbortWithError(http.StatusUnauthorized, err)
			return
		}

		manager := GetManagerInstance()

		canListAll, err := manager.canListCAPIClusters(user)
		if err != nil {
			ginLogger.V(logs.LogInfo).Info(fmt.Sprintf("failed to verify permissions %s: %v", c.Request.URL, err))
			_ = c.AbortWithError(http.StatusUnauthorized, err)
			return
		}

		clusters, err := manager.GetManagedCAPIClusters(c.Request.Context(), canListAll, user)
		if err != nil {
			ginLogger.V(logs.LogInfo).Info(fmt.Sprintf("failed to verify permissions %s: %v", c.Request.URL, err))
			_ = c.AbortWithError(http.StatusUnauthorized, err)
			return
		}

		managedClusterData := getManagedClusterData(clusters, filters)
		sort.Sort(managedClusterData)

		result, err := getClustersInRange(managedClusterData, limit, skip)
		if err != nil {
			ginLogger.V(logs.LogInfo).Info(fmt.Sprintf("bad request %s: %v", c.Request.URL, err))
			_ = c.AbortWithError(http.StatusBadRequest, err)
			return
		}

		response := ClusterResult{
			TotalClusters:   len(managedClusterData),
			ManagedClusters: result,
		}

		// Return JSON response
		c.JSON(http.StatusOK, response)
	}

	getManagedSveltosClusters = func(c *gin.Context) {
		ginLogger.V(logs.LogDebug).Info("get managed SveltosClusters")

		limit, skip := getLimitAndSkipFromQuery(c)
		ginLogger.V(logs.LogDebug).Info(fmt.Sprintf("limit %d skip %d", limit, skip))
		filters, err := getClusterFiltersFromQuery(c)
		if err != nil {
			ginLogger.V(logs.LogInfo).Info(fmt.Sprintf("bad request %s: %v", c.Request.URL, err))
			_ = c.AbortWithError(http.StatusBadRequest, err)
			return
		}
		ginLogger.V(logs.LogDebug).Info(fmt.Sprintf("filters: namespace %q name %q labels %q",
			filters.Namespace, filters.name, filters.labelSelector))

		user, err := validateToken(c)
		if err != nil {
			_ = c.AbortWithError(http.StatusUnauthorized, err)
			return
		}

		manager := GetManagerInstance()

		canListAll, err := manager.canListSveltosClusters(user)
		if err != nil {
			ginLogger.V(logs.LogInfo).Info(fmt.Sprintf("failed to verify permissions %s: %v", c.Request.URL, err))
			_ = c.AbortWithError(http.StatusUnauthorized, err)
			return
		}

		clusters, err := manager.GetManagedSveltosClusters(c.Request.Context(), canListAll, user)
		if err != nil {
			ginLogger.V(logs.LogInfo).Info(fmt.Sprintf("failed to verify permissions %s: %v", c.Request.URL, err))
			_ = c.AbortWithError(http.StatusUnauthorized, err)
			return
		}

		managedClusterData := getManagedClusterData(clusters, filters)
		sort.Sort(managedClusterData)

		result, err := getClustersInRange(managedClusterData, limit, skip)
		if err != nil {
			ginLogger.V(logs.LogInfo).Info(fmt.Sprintf("bad request %s: %v", c.Request.URL, err))
			_ = c.AbortWithError(http.StatusBadRequest, err)
			return
		}

		response := ClusterResult{
			TotalClusters:   len(managedClusterData),
			ManagedClusters: result,
		}

		// Return JSON response
		c.JSON(http.StatusOK, response)
	}

	getDeployedHelmCharts = func(c *gin.Context) {
		ginLogger.V(logs.LogDebug).Info("get deployed HelmCharts")

		namespace, name, clusterType := getClusterFromQuery(c)
		ginLogger.V(logs.LogDebug).Info(fmt.Sprintf("cluster %s:%s/%s", clusterType, namespace, name))

		limit, skip := getLimitAndSkipFromQuery(c)
		ginLogger.V(logs.LogDebug).Info(fmt.Sprintf("limit %d skip %d", limit, skip))

		user, err := validateToken(c)
		if err != nil {
			_ = c.AbortWithError(http.StatusUnauthorized, err)
			return
		}

		manager := GetManagerInstance()

		canGetCluster, err := manager.canGetCluster(namespace, name, user, clusterType)
		if err != nil {
			ginLogger.V(logs.LogInfo).Info(fmt.Sprintf("failed to verify permissions %s: %v", c.Request.URL, err))
			_ = c.AbortWithError(http.StatusUnauthorized, err)
			return
		}

		if !canGetCluster {
			_ = c.AbortWithError(http.StatusUnauthorized, errors.New("no permissions to access this cluster"))
			return
		}

		helmCharts, err := manager.getHelmChartsForCluster(c.Request.Context(),
			namespace, name, clusterType)
		if err != nil {
			ginLogger.V(logs.LogInfo).Info(fmt.Sprintf("bad request %s: %v", c.Request.URL, err))
			_ = c.AbortWithError(http.StatusBadRequest, err)
			return
		}
		sort.Slice(helmCharts, func(i, j int) bool {
			return sortHelmCharts(helmCharts, i, j)
		})

		result, err := getHelmReleaseInRange(helmCharts, limit, skip)
		if err != nil {
			ginLogger.V(logs.LogInfo).Info(fmt.Sprintf("bad request %s: %v", c.Request.URL, err))
			_ = c.AbortWithError(http.StatusBadRequest, err)
			return
		}

		response := HelmReleaseResult{
			TotalHelmReleases: len(helmCharts),
			HelmReleases:      result,
		}

		// Return JSON response
		c.JSON(http.StatusOK, response)
	}

	getDeployedResources = func(c *gin.Context) {
		ginLogger.V(logs.LogDebug).Info("get deployed Kubernetes resources")

		limit, skip := getLimitAndSkipFromQuery(c)
		namespace, name, clusterType := getClusterFromQuery(c)
		ginLogger.V(logs.LogDebug).Info(fmt.Sprintf("cluster %s:%s/%s", clusterType, namespace, name))
		ginLogger.V(logs.LogDebug).Info(fmt.Sprintf("limit %d skip %d", limit, skip))

		user, err := validateToken(c)
		if err != nil {
			_ = c.AbortWithError(http.StatusUnauthorized, err)
			return
		}

		manager := GetManagerInstance()

		canGetCluster, err := manager.canGetCluster(namespace, name, user, clusterType)
		if err != nil {
			ginLogger.V(logs.LogInfo).Info(fmt.Sprintf("failed to verify permissions %s: %v", c.Request.URL, err))
			_ = c.AbortWithError(http.StatusUnauthorized, err)
			return
		}

		if !canGetCluster {
			_ = c.AbortWithError(http.StatusUnauthorized, errors.New("no permissions to access this cluster"))
			return
		}

		resources, err := manager.getResourcesForCluster(c.Request.Context(),
			namespace, name, clusterType)
		if err != nil {
			ginLogger.V(logs.LogInfo).Info(fmt.Sprintf("bad request %s: %v", c.Request.URL, err))
			_ = c.AbortWithError(http.StatusBadRequest, err)
			return
		}
		sort.Slice(resources, func(i, j int) bool {
			return sortResources(resources, i, j)
		})

		result, err := getResourcesInRange(resources, limit, skip)
		if err != nil {
			ginLogger.V(logs.LogInfo).Info(fmt.Sprintf("bad request %s: %v", c.Request.URL, err))
			_ = c.AbortWithError(http.StatusBadRequest, err)
			return
		}

		response := ResourceResult{
			TotalResources: len(resources),
			Resources:      result,
		}

		// Return JSON response
		c.JSON(http.StatusOK, response)
	}

	getClusterStatus = func(c *gin.Context) {
		ginLogger.V(logs.LogDebug).Info("get list of profiles (and their status) matching a cluster")

		failedOnly := getFailedOnlyFromQuery(c)
		limit, skip := getLimitAndSkipFromQuery(c)
		namespace, name, clusterType := getClusterFromQuery(c)
		ginLogger.V(logs.LogDebug).Info(fmt.Sprintf("cluster %s:%s/%s", clusterType, namespace, name))
		ginLogger.V(logs.LogDebug).Info(fmt.Sprintf("limit %d skip %d", limit, skip))
		ginLogger.V(logs.LogDebug).Info(fmt.Sprintf("failed %t", failedOnly))

		user, err := validateToken(c)
		if err != nil {
			_ = c.AbortWithError(http.StatusUnauthorized, err)
			return
		}

		manager := GetManagerInstance()

		canGetCluster, err := manager.canGetCluster(namespace, name, user, clusterType)
		if err != nil {
			ginLogger.V(logs.LogInfo).Info(fmt.Sprintf("failed to verify permissions %s: %v", c.Request.URL, err))
			_ = c.AbortWithError(http.StatusUnauthorized, err)
			return
		}

		if !canGetCluster {
			_ = c.AbortWithError(http.StatusUnauthorized, errors.New("no permissions to access this cluster"))
			return
		}

		clusterProfileStatuses := manager.GetClusterProfileStatusesByCluster(&namespace, &name, clusterType)

		flattenedProfileStatuses := flattenProfileStatuses(clusterProfileStatuses, failedOnly)
		sort.Slice(flattenedProfileStatuses, func(i, j int) bool {
			return sortClusterProfileStatus(flattenedProfileStatuses, i, j)
		})

		result, err := getFlattenedProfileStatusesInRange(flattenedProfileStatuses, limit, skip)
		if err != nil {
			ginLogger.V(logs.LogInfo).Info(fmt.Sprintf("bad request %s: %v", c.Request.URL, err))
			_ = c.AbortWithError(http.StatusBadRequest, err)
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"totalResources": len(flattenedProfileStatuses),
			"profiles":       result,
		})
	}
)

func (m *instance) start(ctx context.Context, port string, logger logr.Logger) {
	ginLogger = logger

	r := gin.Default()
	gin.SetMode(gin.ReleaseMode)

	// Return managed ClusterAPI powered clusters
	r.GET("/capiclusters", getManagedCAPIClusters)
	// Return SveltosClusters
	r.GET("/sveltosclusters", getManagedSveltosClusters)
	// Return helm charts deployed in a given managed cluster
	r.GET("/helmcharts", getDeployedHelmCharts)
	// Return resources deployed in a given managed cluster
	r.GET("/resources", getDeployedResources)
	// Return the specified cluster status
	r.GET("/getClusterStatus", getClusterStatus)

	errCh := make(chan error)

	go func() {
		err := r.Run(port)
		errCh <- err // Send the error on the channel
		ginLogger.V(logs.LogInfo).Info(fmt.Sprintf("run failed: %v", err))
		if killErr := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); killErr != nil {
			panic("kill -TERM failed")
		}
	}()

	for {
		select {
		case <-ctx.Done():
			ginLogger.V(logs.LogInfo).Info("context canceled")
			return
		case <-errCh:
			return
		}
	}
}

func getManagedClusterData(clusters map[corev1.ObjectReference]ClusterInfo, filters *clusterFilters,
) ManagedClusters {

	data := make(ManagedClusters, 0)
	for k := range clusters {
		if filters.Namespace != "" {
			if !strings.Contains(k.Namespace, filters.Namespace) {
				continue
			}
		}

		if filters.name != "" {
			if !strings.Contains(k.Name, filters.name) {
				continue
			}
		}

		if !filters.labelSelector.Empty() {
			if !filters.labelSelector.Matches(labels.Set(clusters[k].Labels)) {
				continue
			}
		}

		data = append(data, ManagedCluster{
			Namespace:   k.Namespace,
			Name:        k.Name,
			ClusterInfo: clusters[k],
		})
	}

	return data
}

func getLimitAndSkipFromQuery(c *gin.Context) (limit, skip int) {
	// Define default values for limit and skip
	limit = maxItems
	skip = 0

	// Get the values from query parameters
	queryLimit := c.Query("limit")
	querySkip := c.Query("skip")

	// Parse the query parameters to int (handle errors)
	var err error
	if queryLimit != "" {
		limit, err = strconv.Atoi(queryLimit)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid limit parameter"})
			return
		}
	}
	if querySkip != "" {
		skip, err = strconv.Atoi(querySkip)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid skip parameter"})
			return
		}
	}

	return
}

func getFailedOnlyFromQuery(c *gin.Context) bool {
	// Define default values for limit and skip
	failedOnly := false

	// Get the values from query parameters
	queryFailed := c.Query("failed")

	// Parse the query parameters to int (handle errors)
	var err error
	if queryFailed != "" {
		failedOnly, err = strconv.ParseBool(queryFailed)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid failed parameter"})
			return failedOnly
		}
	}

	return failedOnly
}

func getClusterFromQuery(c *gin.Context) (namespace, name string, clusterType libsveltosv1beta1.ClusterType) {
	// Get the values from query parameters
	queryNamespace := c.Query("namespace")
	queryName := c.Query("name")
	queryType := c.Query("type")

	// Parse the query parameters to int (handle errors)
	if queryNamespace == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "namespace is required"})
		return
	}
	if queryName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if queryType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cluster type is required"})
		return
	}

	if strings.EqualFold(queryType, string(libsveltosv1beta1.ClusterTypeSveltos)) {
		return queryNamespace, queryName, libsveltosv1beta1.ClusterTypeSveltos
	} else if strings.EqualFold(queryType, string(libsveltosv1beta1.ClusterTypeCapi)) {
		return queryNamespace, queryName, libsveltosv1beta1.ClusterTypeCapi
	}

	c.JSON(http.StatusBadRequest, gin.H{"error": "cluster type is incorrect"})
	return
}

func getTokenFromAuthorizationHeader(c *gin.Context) (string, error) {
	// Get the authorization header value
	authorizationHeader := c.GetHeader("Authorization")

	// Check if the authorization header is present
	if authorizationHeader == "" {
		errorMsg := "authorization header is missing"
		c.JSON(http.StatusUnauthorized, gin.H{"error": errorMsg})
		return "", errors.New(errorMsg)
	}

	// Extract the token from the authorization header
	// Assuming the authorization header format is "Bearer <token>"
	token := authorizationHeader[len("Bearer "):]
	// Check if the token is present
	if token == "" {
		errorMsg := "token is missing"
		c.JSON(http.StatusUnauthorized, gin.H{"error": errorMsg})
		return "", errors.New(errorMsg)
	}

	return token, nil
}

// validateToken:
// - gets token from authorization request. Returns an error if missing
// - validate token. Returns an error if this check fails
// - get and return user info. Returns an error if getting user from token fails
func validateToken(c *gin.Context) (string, error) {
	token, err := getTokenFromAuthorizationHeader(c)
	if err != nil {
		ginLogger.V(logs.LogInfo).Info(fmt.Sprintf("failed to get token from authorization request. Request %s, error %v",
			c.Request.URL, err))
		_ = c.AbortWithError(http.StatusUnauthorized, errors.New("failed to get token from authorization request"))
		return "", err
	}

	manager := GetManagerInstance()
	err = manager.validateToken(token)
	if err != nil {
		ginLogger.V(logs.LogInfo).Info(fmt.Sprintf("failed to validate token: %v", err))
		_ = c.AbortWithError(http.StatusUnauthorized, errors.New("failed to validate token"))
		return "", err
	}

	user, err := manager.getUserFromToken(token)
	if err != nil {
		ginLogger.V(logs.LogInfo).Info(fmt.Sprintf("failed to get user from token: %v", err))
		_ = c.AbortWithError(http.StatusUnauthorized, errors.New("failed to get user from token"))
		return "", err
	}

	ginLogger.V(logs.LogDebug).Info(fmt.Sprintf("user %s", user))

	return user, nil
}
