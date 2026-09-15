package management

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	chatgptwebauth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/chatgptweb"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

const libraryCleanupMaxTargets = coreauth.LibraryCleanupMaxTargets

type libraryCleanupTaskManager = coreauth.LibraryCleanupManager
type libraryCleanupTarget = coreauth.LibraryCleanupTarget
type libraryCleanupResult = coreauth.LibraryCleanupResult
type libraryCleanupTask = coreauth.LibraryCleanupTask

func (h *Handler) libraryTaskDependencies() (*libraryCleanupTaskManager, *coreauth.Manager) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.libraryCleanupTasks == nil {
		if h.authManager != nil {
			h.libraryCleanupTasks = h.authManager.LibraryCleanup()
		} else {
			h.libraryCleanupTasks = &coreauth.LibraryCleanupManager{}
		}
	}
	return h.libraryCleanupTasks, h.authManager
}

func (h *Handler) GetChatGPTWebLibraryCleanup(c *gin.Context) {
	page, err := strconv.Atoi(c.DefaultQuery("page", "1"))
	if err != nil || page < 1 || page > libraryCleanupMaxTargets {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid progress page"})
		return
	}
	tasks, _ := h.libraryTaskDependencies()
	c.Header("Cache-Control", "no-store")
	snapshot := tasks.PublicSnapshot(page)
	c.JSON(http.StatusOK, gin.H{"task": snapshot})
}

func (h *Handler) CancelChatGPTWebLibraryCleanup(c *gin.Context) {
	tasks, _ := h.libraryTaskDependencies()
	task, ok := tasks.Cancel(c.Param("id"))
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "library cleanup task not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"task": task})
}

func (h *Handler) StartChatGPTWebLibraryCleanup(c *gin.Context) {
	var request struct {
		Names       []string `json:"names"`
		All         bool     `json:"all"`
		Confirm     bool     `json:"confirm_delete_all_files"`
		Concurrency int      `json:"concurrency"`
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4<<20)
	if err := decodeStrictJSONBody(c, &request); err != nil {
		c.JSON(chatGPTWebAccountInfoRequestErrorStatus(err), gin.H{"error": "invalid library cleanup request"})
		return
	}
	if !request.Confirm || request.Concurrency < 1 || request.Concurrency > 32 || (request.All && len(request.Names) != 0) || (!request.All && len(request.Names) == 0) || len(request.Names) > libraryCleanupMaxTargets {
		c.JSON(http.StatusBadRequest, gin.H{"error": "confirm deletion, choose names or all, and set concurrency to an integer from 1 to 32"})
		return
	}
	tasks, manager := h.libraryTaskDependencies()
	if manager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "auth manager is unavailable"})
		return
	}
	var ids []string
	names := map[string]string{}
	if !request.All {
		for _, name := range request.Names {
			auth := h.findManagedAuthWithManager(name, manager)
			if auth == nil || !strings.EqualFold(auth.Provider, chatgptwebauth.Provider) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "selection contains a missing or non-ChatGPT Web credential"})
				return
			}
			ids = append(ids, auth.ID)
			names[auth.ID] = name
		}
	}
	var targets []libraryCleanupTarget
	for _, target := range manager.SnapshotMaintenanceTargets(chatgptwebauth.Provider, ids) {
		if name := names[target.ID]; name != "" {
			target.Name = name
		}
		targets = append(targets, libraryCleanupTarget{Name: target.Name, AuthID: target.ID, InstanceID: target.InstanceID})
	}
	if len(targets) == 0 || len(targets) > libraryCleanupMaxTargets {
		c.JSON(http.StatusBadRequest, gin.H{"error": "choose between 1 and 50000 ChatGPT Web credentials"})
		return
	}
	task, err := tasks.Start(targets, request.Concurrency, manager)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"task": task})
}
