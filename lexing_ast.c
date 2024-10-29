

# include <stdio.h>
# include <fcntl.h>
# include <limits.h>
# include <readline/history.h>
# include <readline/readline.h>
# include <signal.h>
# include <stdbool.h>
# include <stdlib.h>
# include <sys/wait.h>
# include <unistd.h>

// # include "../minishell.h"

typedef enum
{
	NODE_PIPE,	   // Pipeline node (connects commands)
	NODE_CMD,		// Command node (includes command name and args)
	NODE_REDIR,	  // Redirection node
	NODE_ARG,		// Argument node
	NODE_WORD,	   // Word node (for command names)
	NODE_ENV,		// Environment variable
	NODE_QUOTE	   // Quoted string
} ast_type;

// AST node structure
typedef struct s_ast_node
{
	ast_type type;
	char *data;
	struct s_ast_node *left;   // Left child
	struct s_ast_node *right;  // Right child
	struct s_ast_node *args;   // For command arguments (linked list)
	struct s_ast_node *next;   // For argument lists
	int redir_type;		   // For redirection nodes (>, <, >>, <<)
} t_ast_node;

// Token structure for lexical analysis
typedef struct s_token
{
	ast_type type;
	char *data;
	struct s_token *next;
} t_token;

void free_ast(t_ast_node *node);

size_t	ft_strlen(const char *str)
{
	size_t	i;

	i = 0;
	while (str[i] != '\0')
		i++;
	return (i);
}

char	*ft_strdup(const char *s1)

{
	char		*str;
	int			i;

	i = 0;
	str = (char *)malloc(sizeof(char) * (ft_strlen(s1)+1));
	if (!str)
		return (NULL);
	while (s1[i] != '\0')
	{
		str[i] = s1[i];
		i++;
	}
	str[i] = '\0';
	return (str);
}

void	ft_bzero(void *s, size_t n)

{
	size_t	i;

	i = 0;
	while (i < n)
	{
		*(char *)(s + i) = 0;
		i++;
	}
}

void	*ft_calloc(size_t count, size_t size)

{
	void	*str;

	str = (void *)malloc(count * size);
	if (str)
	{
		ft_bzero(str, count * size);
	}
	return (str);
}

int	ft_strncmp(const char *s1, const char *s2, size_t n)
{
	size_t	i;

	i = 0;
	while (s1[i] != '\0' && s1[i] == s2[i] && i < n - 1)
	{
		i++;
	}
	if (n == 0)
		return (0);
	return (*(unsigned char *)(s1 + i) - *(unsigned char *)(s2 + i));
}

// Extract word token
char	*ft_substr(char const *s, unsigned int start, size_t len)
{
	size_t	i;
	char	*sub;

	i = 0;
	if (start > ft_strlen(s))
	{
		sub = ft_calloc(1, sizeof(char));
		if (!sub)
			return (NULL);
		return (sub);
	}
	if (ft_strlen(s + start) < len)
		len = ft_strlen(s + start);
	sub = ft_calloc(sizeof(char), len + 1);
	if (!sub)
		return (NULL);
	while (i < len)
		sub[i++] = s[start++];
	return (sub);
}

// Utility functions remain the same as before
bool is_special_char(char c)
{
	return (c == '|' || c == '<' || c == '>' || c == '$');
}

bool is_whitespace(char c)
{
	return (c == ' ' || c == '\t' || c == '\n');
}

bool is_quote(char c)
{
	return (c == '"' || c == '\'');
}

// Skip whitespace and check if end of input
bool skip_whitespace(const char *input, int *i)
{
	while (input[*i] && is_whitespace(input[*i]))
		(*i)++;
	return (input[*i] != '\0');
}

// AST node creation
t_ast_node *create_ast_node(ast_type type, char *data)
{
	t_ast_node *node;

	node = ft_calloc(sizeof(t_ast_node), 1);
	if (!node)
		return (NULL);
	node->type = type;
	node->data = data;
	node->redir_type = 0;
	return (node);
}

// Keep the original create_token function
t_token *create_token(ast_type type, char *data)
{
	t_token *new_token;

	new_token = ft_calloc(sizeof(t_token), 1);
	if (!new_token)
		return (NULL);
	new_token->type = type;
	new_token->data = data;
	new_token->next = NULL;
	return (new_token);
}

// Helper function for special character tokens
char *handle_special_char(const char *input, int *i)
{
	char *data;
		
	if ((input[*i] == '>' && input[*i + 1] == '>') ||
		(input[*i] == '<' && input[*i + 1] == '<'))
	{
		data = ft_calloc(sizeof (char *), 3);
		if (!data)
			return NULL;
		data[0] = input[*i];
		data[1] = input[*i + 1];
		data[2] = '\0';
		(*i)++;
	}
	else
	{
		data = ft_calloc(sizeof (char*), 2);
		if (!data)
			return NULL;
		data[0] = input[*i];
		data[1] = '\0';
	}
	return data;
}

// Get length of word token
int get_word_length(const char *input, int start)
{
	int len;

	len = 0;
	while (input[start + len] && !is_whitespace(input[start + len]) && 
			!is_special_char(input[start + len]))
		len++;
	return len;
}

// Handle word token extraction
char *handle_word(const char *input, int *i)
{
	char *data;
	int len;
	int start;

	start = *i;
	len = get_word_length(input, start);
	data = ft_substr(input, start, len);
	if (!data)
		return NULL;
		
	*i += len - 1;
	return data;
}

// Extract token data with type handling
char *extract_token_data(const char *input, int *i)
{
	if (is_special_char(input[*i]))
		return handle_special_char(input, i);
	return handle_word(input, i);
}
// Modify get_basic_token_type to better handle special characters
ast_type get_basic_token_type(char first_char)
{
	switch (first_char)
	{
		case '|':
			return NODE_PIPE;
		case '>':
		case '<':
			return NODE_REDIR;
		case '$':
			return NODE_ENV;
		case '"':
		case '\'':
			return NODE_QUOTE;
		default:
			return NODE_WORD;
	}
}

// Modify get_token_type to better handle command arguments
ast_type get_token_type(const char *data, const t_token *prev_token)
{
	ast_type basic_type;

	basic_type = get_basic_token_type(data[0]);
		
	// If it's already a special token, return that type
	if (basic_type != NODE_WORD)
		return basic_type;
		
	// If no previous token, or previous token was a pipe or redirection,
	// this word is a command
	if (!prev_token || prev_token->type == NODE_PIPE || 
		prev_token->type == NODE_REDIR)
		return NODE_CMD;
		
	// If previous token was a command or argument, this is an argument
	if (prev_token->type == NODE_CMD || prev_token->type == NODE_ARG)
		return NODE_ARG;
		
	return NODE_WORD;
}

// initialize new token
t_token *init_new_token(const char *input, int *i, t_token *prev_token)
{
	t_token *new_token;
	char *token_data;

	token_data = extract_token_data(input, i);
	if (!token_data)
		return NULL;

	new_token = create_token(get_token_type(token_data, prev_token), token_data);
	if (!new_token)
	{
		free(token_data);
		return NULL;
	}
	return new_token;
}

// Add token to list
void add_token(t_token **head, t_token *new_token)
{
	t_token *current;

	if (!*head)
	{
		*head = new_token;
		return;
	}
	current = *head;
	while (current->next)
		current = current->next;
	current->next = new_token;
}

// Main lexer function
t_token *lexer(const char *input)
{
	t_token *head;
	t_token *new_token;
	t_token *prev_token;
	int i;

	head = NULL;
	prev_token = NULL;
	i = 0;

	while (skip_whitespace(input, &i))
	{
		new_token = init_new_token(input, &i, prev_token);
		if (!new_token)
			return NULL;
		add_token(&head, new_token);
		prev_token = new_token;
		i++;
	}
	return head;
}

// Token list cleanup helper
void cleanup_tokens(t_token *head)
{
	t_token *temp;

	while (head)
	{
		temp = head->next;
		free(head->data);
		free(head);
		head = temp;
	}
}

// Modified parse_command to handle arguments properly
t_ast_node *parse_command(t_token **tokens)
{
	t_ast_node *cmd_node;
	t_ast_node *arg_node;
	t_token *current;

	if (!tokens || !*tokens || (*tokens)->type != NODE_CMD)
		return NULL;
		
	current = *tokens;
	cmd_node = create_ast_node(NODE_CMD, ft_strdup(current->data));
	if (!cmd_node)
		return NULL;
		
	current = current->next;
	// Process arguments until we hit a pipe or redirection or end
	while (current && current->type == NODE_ARG)
	{
		arg_node = create_ast_node(NODE_ARG, ft_strdup(current->data));
		if (!arg_node)
		{
			free_ast(cmd_node);
			return NULL;
		}
		// Add argument to front of list
		arg_node->next = cmd_node->args;
		cmd_node->args = arg_node;
		current = current->next;
	}
		
	*tokens = current;
	return cmd_node;
}

t_ast_node *parse_redirection(t_token **tokens)
{
	t_ast_node *redir_node;
	t_token *current;

	current = *tokens;
	if (!current || !current->next)
		return (NULL);
		
	redir_node = create_ast_node(NODE_REDIR, NULL);
	if (!redir_node)
		return (NULL);
		
	if (ft_strncmp(current->data, ">", 3) == 0)
		redir_node->redir_type = 1;
	else if (ft_strncmp(current->data, "<", 3) == 0)
		redir_node->redir_type = 2;
	else if (ft_strncmp(current->data, ">>", 3) == 0)
		redir_node->redir_type = 3;
	else if (ft_strncmp(current->data, "<<", 3) == 0)
		redir_node->redir_type = 4;
		
	current = current->next;
	redir_node->right = create_ast_node(NODE_WORD, ft_strdup(current->data));
		
	*tokens = current->next;
	return (redir_node);
}
// Parse a command with its redirections
t_ast_node *parse_command_with_redirections(t_token **tokens)
{
	t_ast_node *cmd_node;
	t_ast_node *redir_node;
	t_token *current;

	// First parse the command itself
	cmd_node = parse_command(tokens);
	if (!cmd_node)
		return NULL;

	current = *tokens;
		
	// Handle any redirections attached to this command
	while (current && current->type == NODE_REDIR)
	{
		redir_node = parse_redirection(&current);
		if (!redir_node)
		{
			free_ast(cmd_node);
			return NULL;
		}
		redir_node->left = cmd_node;
		cmd_node = redir_node;
		*tokens = current;
	}

	return cmd_node;
}

// Modified parse_pipeline to keep pipes at the top
t_ast_node *parse_pipeline(t_token **tokens)
{
	t_ast_node *pipe_node;
	t_ast_node *left_cmd;
	t_token *current;

	if (!tokens || !*tokens)
		return NULL;
		
	// Parse the left command (including its redirections)
	left_cmd = parse_command_with_redirections(tokens);
	if (!left_cmd)
		return NULL;
		
	current = *tokens;
		
	// If no pipe, return just the command with its redirections
	if (!current || current->type != NODE_PIPE)
		return left_cmd;
		
	// Create pipe node
	pipe_node = create_ast_node(NODE_PIPE, NULL);
	if (!pipe_node)
	{
		free_ast(left_cmd);
		return NULL;
	}
		
	// Move past pipe token
	*tokens = current->next;
		
	// Recursively parse the right side
	pipe_node->left = left_cmd;
	pipe_node->right = parse_pipeline(tokens);
		
	if (!pipe_node->right)
	{
		free_ast(pipe_node);
		return NULL;
	}
		
	return pipe_node;
}

// can add more parsing modules here
t_ast_node *parse(t_token *tokens)
{
	return parse_pipeline(&tokens);
}

// for Debug/Print
void print_ast(t_ast_node *node, int depth)
{
	int i;

	if (!node)
		return;

	for (i = 0; i < depth; i++)
		printf("  ");

	if(node -> type == NODE_PIPE)
		printf("PIPE\n");
	else if(node -> type == NODE_CMD)
		printf("CMD\n");
	else if(node -> type == NODE_REDIR)
		printf("REDIR\n");
	else if(node -> type == NODE_ARG)
		printf("ARG\n");
	else if(node -> type == NODE_WORD)
		printf("WORD\n");
	else if(node -> type == NODE_ENV)
		printf("ENV\n");
	else if(node -> type == NODE_QUOTE)
		printf("QUOTE\n");

	print_ast(node->args, depth + 1);
	print_ast(node->left, depth + 1);
	print_ast(node->right, depth + 1);
}

void free_ast(t_ast_node *node)
{
	if (!node)
		return;

	free_ast(node->args);
	free_ast(node->left);
	free_ast(node->right);
		
	free(node->data);
	free(node);
}

void free_tokens(t_token *head)
{
	t_token *current;
	t_token *next;

	current = head;
	while (current)
	{
		next = current->next;
		free(current->data);
		free(current);
		current = next;
	}
}

int main(int argc, char **argv)
{
	if (argc != 2)
		return 1;
	
	printf("\ninput: %s\n", argv[1]);

	t_token *tokens = lexer(argv[1]);
	if (!tokens)
		return 1;
		
	t_ast_node *ast = parse(tokens);
	if (ast)
		print_ast(ast, 0);
		
	cleanup_tokens(tokens);
	if (ast)
		free_ast(ast);
	return 0;
}
