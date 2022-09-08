using nextMovie.Data;
using Microsoft.EntityFrameworkCore;
using nextMovie.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
var config     = builder.Configuration;
var DBHost     = config["Host"];
var DBUserName = config["Username"];
var DBDatabase = config["Database"];
var DBPassword = config["Password"];

var connectionString = $"Host={DBHost};Database={DBDatabase};Username={DBUserName};Password={DBPassword};Include Error Detail=True";
// builder.Services.AddDbContext<InstagramContext>(options =>
//     options.UseNpgsql(connectionString)
//            .UseSnakeCaseNamingConvention()
//            .UseLoggerFactory(LoggerFactory.Create(builder => builder.AddConsole()))
//            .EnableSensitiveDataLogging()
//   );

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(connectionString)
           .UseSnakeCaseNamingConvention()
           .UseLoggerFactory(LoggerFactory.Create(builder => builder.AddConsole()))
           .EnableSensitiveDataLogging()
  );
builder.Services.AddDatabaseDeveloperPageExceptionFilter();
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

builder.Services.AddAuthentication(options =>
                  {
                      options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                      options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                      options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                  })
                .AddJwtBearer(options =>
                  {
                      options.SaveToken = true;
                      options.RequireHttpsMetadata = false;
                      options.TokenValidationParameters = new TokenValidationParameters()
                      {
                          ValidateIssuer = true,
                          ValidateAudience = true,
                          ValidAudience = config["JWT:ValidAudience"],
                          ValidIssuer = config["JWT:ValidIssuer"],
                          IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["JWT:Secret"]))
                      };
                  });

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
