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
	"fmt"

	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationapi "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	authenticationv1client "k8s.io/client-go/kubernetes/typed/authentication/v1"
	"k8s.io/client-go/rest"
	certutil "k8s.io/client-go/util/cert"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1beta1"

	libsveltosv1beta1 "github.com/projectsveltos/libsveltos/api/v1beta1"
	logs "github.com/projectsveltos/libsveltos/lib/logsettings"
)

func (m *instance) getKubernetesRestConfig(token string) (*rest.Config, error) {
	const (
		rootCAFile = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	)

	tlsClientConfig := rest.TLSClientConfig{}
	if _, err := certutil.NewPool(rootCAFile); err != nil {
		return nil, err
	} else {
		tlsClientConfig.CAFile = rootCAFile
	}

	return &rest.Config{
		BearerToken:     token,
		Host:            m.config.Host,
		TLSClientConfig: tlsClientConfig,
	}, nil
}

func (m *instance) getUserFromToken(token string) (string, error) {
	config, err := m.getKubernetesRestConfig(token)
	if err != nil {
		m.logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to get restConfig: %v", err))
		return "", err
	}

	authV1Client, err := authenticationv1client.NewForConfig(config)
	if err != nil {
		return "", err
	}

	res, err := authV1Client.SelfSubjectReviews().
		Create(context.TODO(), &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil {
		return "", err
	}

	return res.Status.UserInfo.Username, nil
}

// canListSveltosClusters returns true if user can list all SveltosClusters in all namespaces
func (m *instance) canListSveltosClusters(user string) (bool, error) {
	// Create a Kubernetes clientset
	clientset, err := kubernetes.NewForConfig(m.config)
	if err != nil {
		m.logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to get clientset: %v", err))
		return false, err
	}

	sar := &authorizationapi.SubjectAccessReview{
		Spec: authorizationapi.SubjectAccessReviewSpec{
			ResourceAttributes: &authorizationapi.ResourceAttributes{
				Verb:     "list",
				Group:    libsveltosv1beta1.GroupVersion.Group,
				Version:  libsveltosv1beta1.GroupVersion.Version,
				Resource: libsveltosv1beta1.SveltosClusterKind,
			},
			User: user,
		},
	}

	canI, err := clientset.AuthorizationV1().SubjectAccessReviews().Create(context.TODO(), sar, metav1.CreateOptions{})
	if err != nil {
		m.logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to check clientset permissions: %v", err))
		return false, err
	}

	return canI.Status.Allowed, nil
}

// canGetSveltosCluster returns true if user can access SveltosCluster clusterNamespace:clusterName
func (m *instance) canGetSveltosCluster(clusterNamespace, clusterName, user string) (bool, error) {
	// Create a Kubernetes clientset
	clientset, err := kubernetes.NewForConfig(m.config)
	if err != nil {
		m.logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to get clientset: %v", err))
		return false, err
	}

	sar := &authorizationapi.SubjectAccessReview{
		Spec: authorizationapi.SubjectAccessReviewSpec{
			ResourceAttributes: &authorizationapi.ResourceAttributes{
				Verb:      "get",
				Group:     libsveltosv1beta1.GroupVersion.Group,
				Version:   libsveltosv1beta1.GroupVersion.Version,
				Resource:  libsveltosv1beta1.SveltosClusterKind,
				Namespace: clusterNamespace,
				Name:      clusterName,
			},
			User: user,
		},
	}

	canI, err := clientset.AuthorizationV1().SubjectAccessReviews().Create(context.TODO(), sar, metav1.CreateOptions{})
	if err != nil {
		m.logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to check clientset permissions: %v", err))
		return false, err
	}

	return canI.Status.Allowed, nil
}

// canListCAPIClusters returns true if user can list all CAPI Clusters in all namespaces
func (m *instance) canListCAPIClusters(user string) (bool, error) {
	// Create a Kubernetes clientset
	clientset, err := kubernetes.NewForConfig(m.config)
	if err != nil {
		m.logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to get clientset: %v", err))
		return false, err
	}

	sar := &authorizationapi.SubjectAccessReview{
		Spec: authorizationapi.SubjectAccessReviewSpec{
			ResourceAttributes: &authorizationapi.ResourceAttributes{
				Verb:     "list",
				Group:    clusterv1.GroupVersion.Group,
				Version:  clusterv1.GroupVersion.Version,
				Resource: clusterv1.ClusterKind,
			},
			User: user,
		},
	}

	canI, err := clientset.AuthorizationV1().SubjectAccessReviews().Create(context.TODO(), sar, metav1.CreateOptions{})
	if err != nil {
		m.logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to check clientset permissions: %v", err))
		return false, err
	}

	return canI.Status.Allowed, nil
}

// canGetCAPICluster returns true if user can access CAPI Cluster clusterNamespace:clusterName
func (m *instance) canGetCAPICluster(clusterNamespace, clusterName, user string) (bool, error) {
	// Create a Kubernetes clientset
	clientset, err := kubernetes.NewForConfig(m.config)
	if err != nil {
		m.logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to get clientset: %v", err))
		return false, err
	}

	sar := &authorizationapi.SubjectAccessReview{
		Spec: authorizationapi.SubjectAccessReviewSpec{
			ResourceAttributes: &authorizationapi.ResourceAttributes{
				Verb:      "get",
				Group:     clusterv1.GroupVersion.Group,
				Version:   clusterv1.GroupVersion.Version,
				Resource:  clusterv1.ClusterKind,
				Namespace: clusterNamespace,
				Name:      clusterName,
			},
			User: user,
		},
	}

	canI, err := clientset.AuthorizationV1().SubjectAccessReviews().Create(context.TODO(), sar, metav1.CreateOptions{})
	if err != nil {
		m.logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to check clientset permissions: %v", err))
		return false, err
	}

	return canI.Status.Allowed, nil
}

// canGetCluster verifies whether user has permission to view CAPI/Sveltos Cluster
func (m *instance) canGetCluster(clusterNamespace, clusterName, user string,
	clusterType libsveltosv1beta1.ClusterType) (bool, error) {

	if clusterType == libsveltosv1beta1.ClusterTypeCapi {
		return m.canGetCAPICluster(clusterNamespace, clusterName, user)
	}

	return m.canGetSveltosCluster(clusterNamespace, clusterName, user)
}
