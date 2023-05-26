package handler

import (
	"bytes"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"
	"context"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/ayaco0/mecari-build-hackathon-2023/backend/db"
	"github.com/ayaco0/mecari-build-hackathon-2023/backend/domain"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
	"github.com/sashabaranov/go-openai"
)

var (
	logFile = getEnv("LOGFILE", "access.log")
)

type JwtCustomClaims struct {
	UserID int64 `json:"user_id"`
	jwt.RegisteredClaims
}

type InitializeResponse struct {
	Message string `json:"message"`
}

type registerRequest struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type registerResponse struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

type getUserItemsResponse struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	Price        int64  `json:"price"`
	CategoryName string `json:"category_name"`
}

type getOnSaleItemsResponse struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	Price        int64  `json:"price"`
	CategoryName string `json:"category_name"`
}

type getItemResponse struct {
	ID           int64             `json:"id"`
	Name         string            `json:"name"`
	CategoryID   int64             `json:"category_id"`
	CategoryName string            `json:"category_name"`
	UserID       int64             `json:"user_id"`
	Price        int64             `json:"price"`
	Description  string            `json:"description"`
	Status       domain.ItemStatus `json:"status"`
}

type getCategoriesResponse struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

type sellRequest struct {
	ItemID int64 `json:"item_id"`
}

type addItemRequest struct {
	Name        string `form:"name"`
	CategoryID  int64  `form:"category_id"`
	Price       int64  `form:"price"`
	Description string `form:"description"`
}

type addItemResponse struct {
	ID int64 `json:"id"`
}

type addBalanceRequest struct {
	Balance int64 `json:"balance"`
}

type getBalanceResponse struct {
	Balance int64 `json:"balance"`
}

type loginRequest struct {
	UserID   int64  `json:"user_id"`
	Password string `json:"password"`
}

type loginResponse struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Token string `json:"token"`
}

type CategoryResponse struct {
	Category string `json:"category"`
}

type Handler struct {
	DB       *sql.DB
	UserRepo db.UserRepository
	ItemRepo db.ItemRepository
}

func GetSecret() string {
	if secret := os.Getenv("SECRET"); secret != "" {
		return secret
	}
	return "secret-key"
}

func (h *Handler) Initialize(c echo.Context) error {
	err := os.Truncate(logFile, 0)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, errors.Wrap(err, "Failed to truncate access log"))
	}

	err = db.Initialize(c.Request().Context(), h.DB)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, errors.Wrap(err, "Failed to initialize"))
	}

	return c.JSON(http.StatusOK, InitializeResponse{Message: "Success"})
}

func (h *Handler) AccessLog(c echo.Context) error {
	return c.File(logFile)
}

func (h *Handler) Register(c echo.Context) error {
	// TODO: validation
	// http.StatusBadRequest(400)
	req := new(registerRequest)
	if err := c.Bind(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}
	// 名前またはパスワードが空でないことをチェック
	if req.Name == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Name field is required")
	} 
	if req.Password == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Password field is required")
	} 

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	userID, err := h.UserRepo.AddUser(c.Request().Context(), domain.User{Name: req.Name, Password: string(hash)})
	if err != nil {
		//AddUserで名前の重複チェックを行い、重複がある場合は400を返す
		if httpErr, isHTTPError := err.(*echo.HTTPError); isHTTPError {
			return httpErr
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	return c.JSON(http.StatusOK, registerResponse{ID: userID, Name: req.Name})
}

func (h *Handler) Login(c echo.Context) error {
	ctx := c.Request().Context()
	// TODO: validation
	// http.StatusBadRequest(400)
	req := new(loginRequest)
	if err := c.Bind(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}
	// 入力値（ID・パスワード）の存在チェック
    if req.UserID == 0 || req.Password == "" {
        return echo.NewHTTPError(http.StatusBadRequest, "UserID and password are required")
    }
	// ユーザの存在チェック
	user, err := h.UserRepo.GetUser(ctx, req.UserID)
	if err != nil {
		if err == sql.ErrNoRows {
            return echo.NewHTTPError(http.StatusNotFound, "user not found")
        }
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}
	
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return echo.NewHTTPError(http.StatusUnauthorized, err)
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	// Set custom claims
	claims := &JwtCustomClaims{
		req.UserID,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 72)),
		},
	}
	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Generate encoded token and send it as response.
	encodedToken, err := token.SignedString([]byte(GetSecret()))
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	return c.JSON(http.StatusOK, loginResponse{
		ID:    user.ID,
		Name:  user.Name,
		Token: encodedToken,
	})
}

func (h *Handler) AddItem(c echo.Context) error {
	// TODO: validation
	// http.StatusBadRequest(400)
	ctx := c.Request().Context()

	req := new(addItemRequest)
	if err := c.Bind(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	userID, err := getUserID(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, err)
	}
	file, err := c.FormFile("image")
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	src, err := file.Open()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}
	defer src.Close()

	var dest []byte
	blob := bytes.NewBuffer(dest)
	// TODO: pass very big file
	// http.StatusBadRequest(400)
	if _, err := io.Copy(blob, src); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	_, err = h.ItemRepo.GetCategory(ctx, req.CategoryID)
	if err != nil {
		if err == sql.ErrNoRows {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid categoryID")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	item, err := h.ItemRepo.AddItem(c.Request().Context(), domain.Item{
		Name:        req.Name,
		CategoryID:  req.CategoryID,
		UserID:      userID,
		Price:       req.Price,
		Description: req.Description,
		Image:       blob.Bytes(),
		Status:      domain.ItemStatusInitial,
	})
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	return c.JSON(http.StatusOK, addItemResponse{ID: int64(item.ID)})
}

func (h *Handler) Sell(c echo.Context) error {
	ctx := c.Request().Context()
	req := new(sellRequest)

	if err := c.Bind(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	item, err := h.ItemRepo.GetItem(ctx, req.ItemID)
	if item.Price < 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid price")
	}
	// TODO: not found handling
	// http.StatusPreconditionFailed(412)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	// TODO: check req.UserID and item.UserID
	// http.StatusPreconditionFailed(412)
	// TODO: only update when status is initial
	// http.StatusPreconditionFailed(412)
	if err := h.ItemRepo.UpdateItemStatus(ctx, item.ID, domain.ItemStatusOnSale); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	return c.JSON(http.StatusOK, "successful")
}

func (h *Handler) GetOnSaleItems(c echo.Context) error {
	ctx := c.Request().Context()

	items, err := h.ItemRepo.GetOnSaleItems(ctx)
	if err != nil {
		if err == sql.ErrNoRows {
			return echo.NewHTTPError(http.StatusNotFound, "items not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	var res []getOnSaleItemsResponse
	for _, item := range items {
		cats, err := h.ItemRepo.GetCategories(ctx)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, err)
		}
		for _, cat := range cats {
			if cat.ID == item.CategoryID {
				res = append(res, getOnSaleItemsResponse{ID: item.ID, Name: item.Name, Price: item.Price, CategoryName: cat.Name})
			}
		}
	}

	return c.JSON(http.StatusOK, res)
}

func (h *Handler) GetItem(c echo.Context) error {
	ctx := c.Request().Context()

	itemID, err := strconv.ParseInt(c.Param("itemID"), 10, 64)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	item, err := h.ItemRepo.GetItem(ctx, itemID)
	if err != nil {
		if err == sql.ErrNoRows {
			return echo.NewHTTPError(http.StatusNotFound, "item not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	category, err := h.ItemRepo.GetCategory(ctx, item.CategoryID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}
	return c.JSON(http.StatusOK, getItemResponse{
		ID:           item.ID,
		Name:         item.Name,
		CategoryID:   item.CategoryID,
		CategoryName: category.Name,
		UserID:       item.UserID,
		Price:        item.Price,
		Description:  item.Description,
		Status:       item.Status,
	})
}

func (h *Handler) GetUserItems(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := strconv.ParseInt(c.Param("userID"), 10, 64)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "invalid userID type")
	}

	items, err := h.ItemRepo.GetItemsByUserID(ctx, userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return echo.NewHTTPError(http.StatusNotFound, "items not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	var res []getUserItemsResponse
	for _, item := range items {
		cats, err := h.ItemRepo.GetCategories(ctx)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, err)
		}
		for _, cat := range cats {
			if cat.ID == item.CategoryID {
				res = append(res, getUserItemsResponse{ID: item.ID, Name: item.Name, Price: item.Price, CategoryName: cat.Name})
			}
		}
	}

	return c.JSON(http.StatusOK, res)
}

func (h *Handler) GetCategories(c echo.Context) error {
	ctx := c.Request().Context()

	cats, err := h.ItemRepo.GetCategories(ctx)
	if err != nil {
		if err == sql.ErrNoRows {
			return echo.NewHTTPError(http.StatusNotFound, "categories not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	res := make([]getCategoriesResponse, len(cats))
	for i, cat := range cats {
		res[i] = getCategoriesResponse{ID: cat.ID, Name: cat.Name}
	}

	return c.JSON(http.StatusOK, res)
}

func (h *Handler) GetImage(c echo.Context) error {
	ctx := c.Request().Context()

	// TODO: overflow
	itemID, err := strconv.ParseInt(c.Param("itemID"), 10, 64)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "invalid itemID type")
	}

	// オーバーフローしていると。ここのint32(itemID)がバグって正常に処理ができないはず
	data, err := h.ItemRepo.GetItemImage(ctx, itemID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	return c.Blob(http.StatusOK, "image/jpeg", data)
}

func (h *Handler) AddBalance(c echo.Context) error {
	ctx := c.Request().Context()

	req := new(addBalanceRequest)
	if err := c.Bind(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	} else if req.Balance < 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "balance must be positive");
	}

	userID, err := getUserID(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, err)
	}

	user, err := h.UserRepo.GetUser(ctx, userID)
	// TODO: not found handling
	// http.StatusPreconditionFailed(412)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}
	if err := h.UserRepo.UpdateBalance(ctx, userID, user.Balance+req.Balance); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	return c.JSON(http.StatusOK, "successful")
}

func (h *Handler) GetBalance(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := getUserID(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, err)
	}

	user, err := h.UserRepo.GetUser(ctx, userID)
	// TODO: not found handling
	// http.StatusPreconditionFailed(412)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	return c.JSON(http.StatusOK, getBalanceResponse{Balance: user.Balance})
}

func (h *Handler) Purchase(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := getUserID(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, err)
	}

	// TODO: overflow
	itemID, err := strconv.ParseInt(c.Param("itemID"), 10, 64)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	// TODO: update only when item status is on sale
	// http.StatusPreconditionFailed(412)

	// オーバーフローしていると。ここのint32(itemID)がバグって正常に処理ができないはず
	if err := h.ItemRepo.UpdateItemStatus(ctx, itemID, domain.ItemStatusSoldOut); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	user, err := h.UserRepo.GetUser(ctx, userID)
	// TODO: not found handling
	// http.StatusPreconditionFailed(412)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	item, err := h.ItemRepo.GetItem(ctx, itemID)
	// TODO: not found handling
	// http.StatusPreconditionFailed(412)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	// TODO: if it is fail here, item status is still sold
	// TODO: balance consistency
	// TODO: not to buy own items. 自身の商品を買おうとしていたら、http.StatusPreconditionFailed(412)
	if err := h.UserRepo.UpdateBalance(ctx, userID, user.Balance-item.Price); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	sellerID := item.UserID

	seller, err := h.UserRepo.GetUser(ctx, sellerID)
	// TODO: not found handling
	// http.StatusPreconditionFailed(412)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	if err := h.UserRepo.UpdateBalance(ctx, sellerID, seller.Balance+item.Price); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	return c.JSON(http.StatusOK, "successful")
}

func getUserID(c echo.Context) (int64, error) {
	user := c.Get("user").(*jwt.Token)
	if user == nil {
		return -1, fmt.Errorf("invalid token")
	}
	claims := user.Claims.(*JwtCustomClaims)
	if claims == nil {
		return -1, fmt.Errorf("invalid token")
	}

	return claims.UserID, nil
}

func getEnv(key string, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func extractCategory(response string, categories []string) string {
	response = strings.ToLower(response)

	// カテゴリ名の抽出
	for _, category := range categories {
		if strings.Contains(response, category) {
			return category
		}
	}

	// 該当するカテゴリがない場合
	return "category not found"
}

func (h *Handler) CategorizeText(ctx context.Context, text string) (string, error) {
    // OpenAI クライアントを作成
    client := openai.NewClient("YOUR_API_KEY")
	msgs := []openai.ChatCompletionMessage{}
	
	// カテゴリ一覧を取得
	cats, err := h.ItemRepo.GetCategories(ctx)
	categories := make([]string, len(cats))
	for i, cat := range cats {
		categories[i] = cat.Name
	}
	fmt.Println(categories)
	categoryString := strings.Join(categories, ", ")
	fmt.Println(categoryString)

	// promptを作成
	text = "商品カテゴリ名一覧は"+categoryString+"です。以下の商品説明文から商品のカテゴリ名を推定してください。"+text
	msgs = append(msgs, openai.ChatCompletionMessage{Role: openai.ChatMessageRoleUser, Content: text})
    
	// GPT-3.5 モデルに対してリクエストを送信
	resp, err := client.CreateChatCompletion(
		ctx,
		openai.ChatCompletionRequest{Model: openai.GPT3Dot5Turbo, Messages: msgs},
	)
    if err != nil {
        return "", err
    }

    // レスポンスから推定されたカテゴリを取得
    response := resp.Choices[0].Message.Content
	category := extractCategory(response, categories)

    return category, nil
}

func (h *Handler) SuggestCategory(c echo.Context) error {
	ctx := c.Request().Context()
	text := c.QueryParam("text")

	category, err := h.CategorizeText(ctx, text)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, err)
	}

	res := CategoryResponse{
		Category: category,
	}

	return c.JSON(http.StatusOK, res)
}